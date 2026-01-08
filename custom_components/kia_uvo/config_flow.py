"""Config flow for Hyundai / Kia Connect integration."""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from hyundai_kia_connect_api import Token, VehicleManager
from hyundai_kia_connect_api.exceptions import AuthenticationError
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_PASSWORD,
    CONF_PIN,
    CONF_REGION,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError

from .const import (
    BRANDS,
    CONF_BRAND,
    CONF_DEVICE_ID,
    CONF_FORCE_REFRESH_INTERVAL,
    CONF_NO_FORCE_REFRESH_HOUR_FINISH,
    CONF_NO_FORCE_REFRESH_HOUR_START,
    CONF_REFRESH_TOKEN,
    DEFAULT_FORCE_REFRESH_INTERVAL,
    DEFAULT_NO_FORCE_REFRESH_HOUR_FINISH,
    DEFAULT_NO_FORCE_REFRESH_HOUR_START,
    DEFAULT_PIN,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    REGIONS,
    CONF_ENABLE_GEOLOCATION_ENTITY,
    CONF_USE_EMAIL_WITH_GEOCODE_API,
    DEFAULT_ENABLE_GEOLOCATION_ENTITY,
    DEFAULT_USE_EMAIL_WITH_GEOCODE_API,
    REGION_EUROPE,
    REGION_USA,
    BRAND_HYUNDAI,
    BRAND_KIA,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_PIN, default=DEFAULT_PIN): str,
        vol.Required(CONF_REGION): vol.In(REGIONS),
        vol.Required(CONF_BRAND): vol.In(BRANDS),
    }
)

STEP_REGION_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_REGION): vol.In(REGIONS),
        vol.Required(CONF_BRAND): vol.In(BRANDS),
    }
)

STEP_CREDENTIALS_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_PIN, default=DEFAULT_PIN): str,
    }
)

OPTIONS_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(
            vol.Coerce(int), vol.Range(min=15, max=999)
        ),
        vol.Required(
            CONF_FORCE_REFRESH_INTERVAL,
            default=DEFAULT_FORCE_REFRESH_INTERVAL,
        ): vol.All(vol.Coerce(int), vol.Range(min=90, max=9999)),
        vol.Required(
            CONF_NO_FORCE_REFRESH_HOUR_START,
            default=DEFAULT_NO_FORCE_REFRESH_HOUR_START,
        ): vol.All(vol.Coerce(int), vol.Range(min=0, max=23)),
        vol.Required(
            CONF_NO_FORCE_REFRESH_HOUR_FINISH,
            default=DEFAULT_NO_FORCE_REFRESH_HOUR_FINISH,
        ): vol.All(vol.Coerce(int), vol.Range(min=0, max=23)),
        vol.Optional(
            CONF_ENABLE_GEOLOCATION_ENTITY,
            default=DEFAULT_ENABLE_GEOLOCATION_ENTITY,
        ): bool,
        vol.Optional(
            CONF_USE_EMAIL_WITH_GEOCODE_API,
            default=DEFAULT_USE_EMAIL_WITH_GEOCODE_API,
        ): bool,
    }
)


async def validate_input(hass: HomeAssistant, user_input: dict[str, Any]) -> Token:
    """Validate the user input allows us to connect."""
    try:
        api = VehicleManager.get_implementation_by_region_brand(
            user_input[CONF_REGION],
            user_input[CONF_BRAND],
            language=hass.config.language,
        )
        
        # Check if we have stored tokens to pass in
        existing_token = None
        if user_input.get(CONF_REFRESH_TOKEN):
            existing_token = Token(
                username=user_input[CONF_USERNAME],
                password=user_input[CONF_PASSWORD],
                access_token="",
                refresh_token=user_input[CONF_REFRESH_TOKEN],
                device_id=user_input.get(CONF_DEVICE_ID),
                valid_until=None,
            )
        
        token: Token = await hass.async_add_executor_job(
            api.login,
            user_input[CONF_USERNAME],
            user_input[CONF_PASSWORD],
            existing_token,  # Pass existing token if available
            user_input.get("otp_handler"),  # OTP handler callback
            user_input.get(CONF_PIN, ""),
        )

        if token is None:
            raise InvalidAuth

        return token
    except AuthenticationError as err:
        raise InvalidAuth from err


class HyundaiKiaConnectOptionFlowHandler(config_entries.OptionsFlow):
    """Handle an option flow for Hyundai / Kia Connect."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle options init setup."""

        if user_input is not None:
            return self.async_create_entry(
                title=self.config_entry.title, data=user_input
            )

        return self.async_show_form(
            step_id="init",
            data_schema=self.add_suggested_values_to_schema(
                OPTIONS_SCHEMA, self.config_entry.options
            ),
        )


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Hyundai / Kia Connect."""

    VERSION = 3  # Bumped for OTP token storage
    reauth_entry: ConfigEntry | None = None

    def __init__(self):
        """Initialize the config flow."""
        self._region_data = None
        self._credentials = None
        # OTP flow state
        self._otp_context = None
        self._otp_response = None

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry):
        """Initiate options flow instance."""
        return HyundaiKiaConnectOptionFlowHandler()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step for region/brand selection."""
        if user_input is None:
            return self.async_show_form(
                step_id="user", data_schema=STEP_REGION_DATA_SCHEMA
            )

        self._region_data = user_input
        self._region_data = user_input
        if REGIONS[self._region_data[CONF_REGION]] == REGION_EUROPE and (
            BRANDS[self._region_data[CONF_BRAND]] == BRAND_KIA
            or BRANDS[self._region_data[CONF_BRAND]] == BRAND_HYUNDAI
        ):
            return await self.async_step_credentials_token()
        return await self.async_step_credentials_password()

    async def async_step_credentials_password(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the credentials step."""
        errors = {}

        if user_input is not None:
            # Store credentials for potential OTP flow
            self._credentials = user_input
            # Combine region data with credentials
            full_config = {**self._region_data, **user_input}

            try:
                # Create an OTP handler that will signal we need OTP
                otp_needed = {"needed": False, "context": None}
                
                def otp_handler(context):
                    """Handle OTP callback from the API."""
                    stage = context.get("stage")
                    if stage == "choose_destination":
                        # Signal that OTP is needed
                        otp_needed["needed"] = True
                        otp_needed["context"] = context
                        # Raise to break out of login
                        raise OTPRequired(context)
                    return {}
                
                full_config["otp_handler"] = otp_handler
                
                token = await validate_input(self.hass, full_config)
                
                # Success without OTP - save token info
                full_config[CONF_REFRESH_TOKEN] = getattr(token, "refresh_token", None)
                full_config[CONF_DEVICE_ID] = getattr(token, "device_id", None)
                # Remove the otp_handler before storing
                full_config.pop("otp_handler", None)
                
                return await self._async_create_or_update_entry(full_config, user_input)
                
            except OTPRequired as otp_ctx:
                # OTP is required - store context and proceed to OTP selection
                self._otp_context = otp_ctx.context
                return await self.async_step_otp_select()
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="credentials_password",
            data_schema=STEP_CREDENTIALS_DATA_SCHEMA,
            errors=errors,
        )

    async def async_step_otp_select(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle OTP destination selection."""
        errors = {}
        
        if user_input is not None:
            # Store the selected OTP method and proceed to send OTP
            self._otp_method = user_input.get("otp_method", "EMAIL")
            
            try:
                # Now we need to complete the login with OTP
                full_config = {**self._region_data, **self._credentials}
                
                api = VehicleManager.get_implementation_by_region_brand(
                    full_config[CONF_REGION],
                    full_config[CONF_BRAND],
                    language=self.hass.config.language,
                )
                
                # Send OTP request
                otp_key = self._otp_context.get("otpKey") if self._otp_context else None
                
                # We need to re-initiate login and handle the OTP flow
                # The API will send the OTP when we provide the handler
                self._pending_otp = {
                    "api": api,
                    "otp_key": otp_key,
                    "method": self._otp_method,
                }
                
                # Call the API to send OTP
                await self.hass.async_add_executor_job(
                    api._send_otp,
                    self._otp_context.get("otpKey"),
                    self._otp_method,
                    self._otp_context.get("xid", ""),
                )
                
                return await self.async_step_otp_code()
                
            except Exception as ex:  # pylint: disable=broad-except
                _LOGGER.exception("Error sending OTP: %s", ex)
                errors["base"] = "otp_send_failed"
        
        # Build options based on what's available
        has_email = self._otp_context.get("hasEmail", True) if self._otp_context else True
        has_phone = self._otp_context.get("hasPhone", False) if self._otp_context else False
        
        email_display = self._otp_context.get("email", "Email") if self._otp_context else "Email"
        phone_display = self._otp_context.get("phone", "Phone") if self._otp_context else "Phone"
        
        options = {}
        if has_email:
            options["EMAIL"] = f"Email ({email_display})"
        if has_phone:
            options["PHONE"] = f"Phone ({phone_display})"
        
        if not options:
            options["EMAIL"] = "Email"
        
        schema = vol.Schema({
            vol.Required("otp_method", default="EMAIL"): vol.In(options),
        })
        
        return self.async_show_form(
            step_id="otp_select",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "email": email_display,
                "phone": phone_display,
            },
        )

    async def async_step_otp_code(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle OTP code entry."""
        errors = {}
        
        if user_input is not None:
            otp_code = user_input.get("otp_code", "").strip()
            
            if not otp_code:
                errors["base"] = "otp_code_required"
            else:
                try:
                    full_config = {**self._region_data, **self._credentials}
                    
                    api = VehicleManager.get_implementation_by_region_brand(
                        full_config[CONF_REGION],
                        full_config[CONF_BRAND],
                        language=self.hass.config.language,
                    )
                    
                    # Verify OTP and get session
                    otp_key = self._otp_context.get("otpKey") if self._otp_context else None
                    xid = self._otp_context.get("xid", "") if self._otp_context else ""
                    
                    sid, rmtoken = await self.hass.async_add_executor_job(
                        api._verify_otp,
                        otp_key,
                        otp_code,
                        xid,
                    )
                    
                    # Complete login with OTP tokens
                    final_sid = await self.hass.async_add_executor_job(
                        api._complete_login_with_otp,
                        full_config[CONF_USERNAME],
                        full_config[CONF_PASSWORD],
                        sid,
                        rmtoken,
                    )
                    
                    # Store the tokens
                    full_config[CONF_REFRESH_TOKEN] = rmtoken
                    full_config[CONF_DEVICE_ID] = getattr(api, "device_id", None)
                    
                    return await self._async_create_or_update_entry(full_config, self._credentials)
                    
                except AuthenticationError:
                    errors["base"] = "invalid_otp"
                except Exception as ex:  # pylint: disable=broad-except
                    _LOGGER.exception("Error verifying OTP: %s", ex)
                    errors["base"] = "otp_verify_failed"
        
        schema = vol.Schema({
            vol.Required("otp_code"): str,
        })
        
        notification_type = getattr(self, "_otp_method", "email").lower()
        
        return self.async_show_form(
            step_id="otp_code",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "notification_type": notification_type,
            },
        )

    async def _async_create_or_update_entry(
        self, full_config: dict[str, Any], user_input: dict[str, Any]
    ) -> FlowResult:
        """Create or update the config entry."""
        if self.reauth_entry is None:
            title = f"{BRANDS[self._region_data[CONF_BRAND]]} {REGIONS[self._region_data[CONF_REGION]]} {user_input[CONF_USERNAME]}"
            await self.async_set_unique_id(
                hashlib.sha256(title.encode("utf-8")).hexdigest()
            )
            self._abort_if_unique_id_configured()
            return self.async_create_entry(title=title, data=full_config)
        else:
            self.hass.config_entries.async_update_entry(
                self.reauth_entry, data=full_config
            )
            await self.hass.config_entries.async_reload(
                self.reauth_entry.entry_id
            )
            return self.async_abort(reason="reauth_successful")

    async def async_step_credentials_token(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the credentials step for token-based auth (Europe)."""
        errors = {}

        if user_input is not None:
            # Combine region data with credentials
            full_config = {**self._region_data, **user_input}

            try:
                token = await validate_input(self.hass, full_config)
                
                # Store token info
                full_config[CONF_REFRESH_TOKEN] = getattr(token, "refresh_token", None)
                full_config[CONF_DEVICE_ID] = getattr(token, "device_id", None)
                
                return await self._async_create_or_update_entry(full_config, user_input)
                
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="credentials_token",
            data_schema=STEP_CREDENTIALS_DATA_SCHEMA,
            errors=errors,
        )

    async def async_step_reauth(self, user_input=None):
        """Perform reauth upon an API authentication error."""
        self.reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None):
        """Dialog that informs the user that reauth is required."""
        if user_input is None:
            return self.async_show_form(
                step_id="reauth_confirm",
                data_schema=vol.Schema({}),
            )
        self._reauth_config = True
        return await self.async_step_user()


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""


class OTPRequired(Exception):
    """Exception to indicate OTP is required."""
    
    def __init__(self, context: dict):
        """Initialize with OTP context."""
        self.context = context
        super().__init__("OTP required")
