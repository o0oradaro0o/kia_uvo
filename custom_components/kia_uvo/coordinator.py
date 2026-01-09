"""Coordinator for Hyundai / Kia Connect integration."""

from __future__ import annotations

from datetime import timedelta
import datetime as dt
import traceback
import logging
import asyncio
import uuid
import time
import datetime as dt
import types

from hyundai_kia_connect_api import (
    VehicleManager,
    ClimateRequestOptions,
    WindowRequestOptions,
    ScheduleChargingClimateRequestOptions,
    Token,
)
from hyundai_kia_connect_api.exceptions import AuthenticationError

from homeassistant.exceptions import ConfigEntryAuthFailed

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_PASSWORD,
    CONF_PIN,
    CONF_REGION,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .const import (
    CONF_BRAND,
    CONF_DEVICE_ID,
    CONF_FORCE_REFRESH_INTERVAL,
    CONF_NO_FORCE_REFRESH_HOUR_FINISH,
    CONF_NO_FORCE_REFRESH_HOUR_START,
    CONF_REFRESH_TOKEN,
    DEFAULT_FORCE_REFRESH_INTERVAL,
    DEFAULT_NO_FORCE_REFRESH_HOUR_FINISH,
    DEFAULT_NO_FORCE_REFRESH_HOUR_START,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    DEFAULT_ENABLE_GEOLOCATION_ENTITY,
    DEFAULT_USE_EMAIL_WITH_GEOCODE_API,
    CONF_USE_EMAIL_WITH_GEOCODE_API,
    CONF_ENABLE_GEOLOCATION_ENTITY,
    REGION_USA,
)

def _get_usa_headers(device_id):
    """Generate correct headers for Kia USA API."""
    offset = time.localtime().tm_gmtoff / 60 / 60
    client_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, device_id)
    
    headers = {
        "content-type": "application/json;charset=utf-8",
        "accept": "application/json",
        "accept-encoding": "gzip, deflate, br",
        "accept-language": "en-US,en;q=0.9",
        "accept-charset": "utf-8",
        "apptype": "L",
        "appversion": "7.22.0",
        "clientid": "SPACL716-APL",
        "clientuuid": str(client_uuid),
        "from": "SPA",
        "host": "api.owners.kia.com",
        "language": "0",
        "offset": str(int(offset)),
        "ostype": "iOS",
        "osversion": "15.8.5",
        "phonebrand": "iPhone",
        "secretkey": "sydnat-9kykci-Kuhtep-h5nK",
        "to": "APIGW",
        "tokentype": "A",
        "user-agent": "KIAPrimo_iOS/37 CFNetwork/1335.0.3.4 Darwin/21.6.0",
    }
    date = dt.datetime.now(tz=dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    headers["date"] = date
    headers["deviceid"] = device_id
    return headers

_LOGGER = logging.getLogger(__name__)


class HyundaiKiaConnectDataUpdateCoordinator(DataUpdateCoordinator):
    """Class to manage fetching data from the API."""

    def __init__(self, hass: HomeAssistant, config_entry: ConfigEntry) -> None:
        """Initialize."""
        self.platforms: set[str] = set()
        self.config_entry = config_entry
        self.hass = hass
        self.vehicle_manager = VehicleManager(
            region=config_entry.data.get(CONF_REGION),
            brand=config_entry.data.get(CONF_BRAND),
            username=config_entry.data.get(CONF_USERNAME),
            password=config_entry.data.get(CONF_PASSWORD),
            pin=config_entry.data.get(CONF_PIN),
            geocode_api_enable=config_entry.options.get(
                CONF_ENABLE_GEOLOCATION_ENTITY, DEFAULT_ENABLE_GEOLOCATION_ENTITY
            ),
            geocode_api_use_email=config_entry.options.get(
                CONF_USE_EMAIL_WITH_GEOCODE_API, DEFAULT_USE_EMAIL_WITH_GEOCODE_API
            ),
            language=hass.config.language,
        )
        
        
        # Hydrate device_id explicitly from storage if available
        stored_device_id = config_entry.data.get(CONF_DEVICE_ID)
        if stored_device_id and hasattr(self.vehicle_manager.api, "device_id"):
            _LOGGER.debug(f"{DOMAIN} - Hydrating API device_id: {stored_device_id}")
            self.vehicle_manager.api.device_id = stored_device_id

        # Patch API headers for USA region
        if self.vehicle_manager.api.__class__.__name__ == "KiaUvoApiUSA":
             _LOGGER.debug(f"{DOMAIN} - Monkeypatching API headers and session for KiaUvoApiUSA")
             
             # 1. Robust method monkeypatch using types.MethodType
             api = self.vehicle_manager.api
             def patched_api_headers(self_api):
                 return _get_usa_headers(self_api.device_id)
             
             api.api_headers = types.MethodType(patched_api_headers, api)

             # 2. Wrap session.post to log all requests/responses for troubleshooting
             original_post = api.session.post
             def patched_post(url, **kwargs):
                 _LOGGER.debug(f"{DOMAIN} - API Request: {url} | Kwargs: {kwargs}")
                 resp = original_post(url, **kwargs)
                 _LOGGER.debug(f"{DOMAIN} - API Response: {resp.status_code} | Body: {resp.text}")
                 return resp
             api.session.post = patched_post
        
        stored_refresh_token = config_entry.data.get(CONF_REFRESH_TOKEN)
        if stored_refresh_token:
            _LOGGER.debug(f"{DOMAIN} - Using stored refresh token for authentication")
            self.vehicle_manager.token = Token(
                username=config_entry.data.get(CONF_USERNAME),
                password=config_entry.data.get(CONF_PASSWORD),
                access_token="",  # Will be refreshed
                refresh_token=stored_refresh_token,
                device_id=stored_device_id,
                valid_until=dt.datetime.min.replace(tzinfo=dt.timezone.utc),  # Force refresh
            )
        self.scan_interval: int = (
            config_entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL) * 60
        )
        self.force_refresh_interval: int = (
            config_entry.options.get(
                CONF_FORCE_REFRESH_INTERVAL, DEFAULT_FORCE_REFRESH_INTERVAL
            )
            * 60
        )
        self.no_force_refresh_hour_start: int = config_entry.options.get(
            CONF_NO_FORCE_REFRESH_HOUR_START, DEFAULT_NO_FORCE_REFRESH_HOUR_START
        )
        self.no_force_refresh_hour_finish: int = config_entry.options.get(
            CONF_NO_FORCE_REFRESH_HOUR_FINISH, DEFAULT_NO_FORCE_REFRESH_HOUR_FINISH
        )
        self.enable_geolocation_entity = config_entry.options.get(
            CONF_ENABLE_GEOLOCATION_ENTITY, DEFAULT_ENABLE_GEOLOCATION_ENTITY
        )
        self.use_email_with_geocode_api = config_entry.options.get(
            CONF_USE_EMAIL_WITH_GEOCODE_API, DEFAULT_USE_EMAIL_WITH_GEOCODE_API
        )

        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(
                seconds=min(self.scan_interval, self.force_refresh_interval)
            ),
        )

    async def _async_update_data(self):
        """Update data via library. Called by update_coordinator periodically.

        Allow to update for the first time without further checking
        Allow force update, if time diff between latest update and `now` is greater than force refresh delta
        """
        try:
            await self.async_check_and_refresh_token()
        except AuthenticationError as AuthError:
            raise ConfigEntryAuthFailed(AuthError) from AuthError
        current_hour = dt_util.now().hour

        if (
            (self.no_force_refresh_hour_start <= self.no_force_refresh_hour_finish)
            and (
                current_hour < self.no_force_refresh_hour_start
                or current_hour >= self.no_force_refresh_hour_finish
            )
        ) or (
            (self.no_force_refresh_hour_start >= self.no_force_refresh_hour_finish)
            and (
                current_hour < self.no_force_refresh_hour_start
                and current_hour >= self.no_force_refresh_hour_finish
            )
        ):
            try:
                await self.hass.async_add_executor_job(
                    self.vehicle_manager.check_and_force_update_vehicles,
                    self.force_refresh_interval,
                )
            except Exception:
                try:
                    _LOGGER.exception(
                        f"Force update failed, falling back to cached: {traceback.format_exc()}"
                    )
                    await self.hass.async_add_executor_job(
                        self.vehicle_manager.update_all_vehicles_with_cached_state
                    )
                except Exception:
                    _LOGGER.exception(f"Cached update failed: {traceback.format_exc()}")
                    raise UpdateFailed(
                        f"Error communicating with API: {traceback.format_exc()}"
                    )

        else:
            await self.hass.async_add_executor_job(
                self.vehicle_manager.update_all_vehicles_with_cached_state
            )

        return self.data

    async def async_update_all(self) -> None:
        """Update vehicle data."""
        await self.async_check_and_refresh_token()
        await self.hass.async_add_executor_job(
            self.vehicle_manager.update_all_vehicles_with_cached_state
        )
        await self.async_refresh()

    async def async_force_update_all(self) -> None:
        """Force refresh vehicle data and update it."""
        await self.async_check_and_refresh_token()
        await self.hass.async_add_executor_job(
            self.vehicle_manager.force_refresh_all_vehicles_states
        )
        await self.async_refresh()

    async def async_check_and_refresh_token(self):
        """Refresh token if needed via library."""
        token_refreshed = await self.hass.async_add_executor_job(
            self.vehicle_manager.check_and_refresh_token
        )
        
        # If token was refreshed, persist the new tokens to config entry
        if token_refreshed and self.vehicle_manager.token:
            token = self.vehicle_manager.token
            new_refresh_token = getattr(token, "refresh_token", None)
            new_device_id = getattr(token, "device_id", None)
            
            current_refresh_token = self.config_entry.data.get(CONF_REFRESH_TOKEN)
            
            # Only update if tokens have changed
            if new_refresh_token and new_refresh_token != current_refresh_token:
                _LOGGER.debug(f"{DOMAIN} - Persisting updated refresh token to config entry")
                new_data = dict(self.config_entry.data)
                new_data[CONF_REFRESH_TOKEN] = new_refresh_token
                if new_device_id:
                    new_data[CONF_DEVICE_ID] = new_device_id
                self.hass.config_entries.async_update_entry(
                    self.config_entry, data=new_data
                )

    async def async_await_action_and_refresh(self, vehicle_id, action_id):
        try:
            await asyncio.sleep(5)
            await self.hass.async_add_executor_job(
                self.vehicle_manager.check_action_status,
                vehicle_id,
                action_id,
                True,
                60,
            )
        finally:
            await self.async_refresh()

    async def async_lock_vehicle(self, vehicle_id: str):
        await self.async_check_and_refresh_token()
        action_id = await self.hass.async_add_executor_job(
            self.vehicle_manager.lock, vehicle_id
        )
        self.hass.async_create_task(
            self.async_await_action_and_refresh(vehicle_id, action_id)
        )

    async def async_unlock_vehicle(self, vehicle_id: str):
        await self.async_check_and_refresh_token()
        action_id = await self.hass.async_add_executor_job(
            self.vehicle_manager.unlock, vehicle_id
        )
        self.hass.async_create_task(
            self.async_await_action_and_refresh(vehicle_id, action_id)
        )

    async def async_open_charge_port(self, vehicle_id: str):
        await self.async_check_and_refresh_token()
        action_id = await self.hass.async_add_executor_job(
            self.vehicle_manager.open_charge_port, vehicle_id
        )
        self.hass.async_create_task(
            self.async_await_action_and_refresh(vehicle_id, action_id)
        )

    async def async_close_charge_port(self, vehicle_id: str):
        await self.async_check_and_refresh_token()
        action_id = await self.hass.async_add_executor_job(
            self.vehicle_manager.close_charge_port, vehicle_id
        )
        self.hass.async_create_task(
            self.async_await_action_and_refresh(vehicle_id, action_id)
        )

    async def async_start_climate(
        self, vehicle_id: str, climate_options: ClimateRequestOptions
    ):
        await self.async_check_and_refresh_token()
        action_id = await self.hass.async_add_executor_job(
            self.vehicle_manager.start_climate, vehicle_id, climate_options
        )
        self.hass.async_create_task(
            self.async_await_action_and_refresh(vehicle_id, action_id)
        )

    async def async_stop_climate(self, vehicle_id: str):
        await self.async_check_and_refresh_token()
        action_id = await self.hass.async_add_executor_job(
            self.vehicle_manager.stop_climate, vehicle_id
        )
        self.hass.async_create_task(
            self.async_await_action_and_refresh(vehicle_id, action_id)
        )

    async def async_start_charge(self, vehicle_id: str):
        await self.async_check_and_refresh_token()
        action_id = await self.hass.async_add_executor_job(
            self.vehicle_manager.start_charge, vehicle_id
        )
        self.hass.async_create_task(
            self.async_await_action_and_refresh(vehicle_id, action_id)
        )

    async def async_stop_charge(self, vehicle_id: str):
        await self.async_check_and_refresh_token()
        action_id = await self.hass.async_add_executor_job(
            self.vehicle_manager.stop_charge, vehicle_id
        )
        self.hass.async_create_task(
            self.async_await_action_and_refresh(vehicle_id, action_id)
        )

    async def async_set_charge_limits(self, vehicle_id: str, ac: int, dc: int):
        await self.async_check_and_refresh_token()
        action_id = await self.hass.async_add_executor_job(
            self.vehicle_manager.set_charge_limits, vehicle_id, ac, dc
        )
        self.hass.async_create_task(
            self.async_await_action_and_refresh(vehicle_id, action_id)
        )

    async def async_set_charging_current(self, vehicle_id: str, level: int):
        await self.async_check_and_refresh_token()
        action_id = await self.hass.async_add_executor_job(
            self.vehicle_manager.set_charging_current, vehicle_id, level
        )
        self.hass.async_create_task(
            self.async_await_action_and_refresh(vehicle_id, action_id)
        )

    async def async_schedule_charging_and_climate(
        self, vehicle_id: str, schedule_options: ScheduleChargingClimateRequestOptions
    ):
        await self.async_check_and_refresh_token()
        action_id = await self.hass.async_add_executor_job(
            self.vehicle_manager.schedule_charging_and_climate,
            vehicle_id,
            schedule_options,
        )
        self.hass.async_create_task(
            self.async_await_action_and_refresh(vehicle_id, action_id)
        )

    async def async_start_hazard_lights(self, vehicle_id: str):
        await self.async_check_and_refresh_token()
        action_id = await self.hass.async_add_executor_job(
            self.vehicle_manager.start_hazard_lights, vehicle_id
        )
        self.hass.async_create_task(
            self.async_await_action_and_refresh(vehicle_id, action_id)
        )

    async def async_start_hazard_lights_and_horn(self, vehicle_id: str):
        await self.async_check_and_refresh_token()
        action_id = await self.hass.async_add_executor_job(
            self.vehicle_manager.start_hazard_lights_and_horn,
            vehicle_id,
        )
        self.hass.async_create_task(
            self.async_await_action_and_refresh(vehicle_id, action_id)
        )

    async def async_start_valet_mode(self, vehicle_id: str):
        await self.async_check_and_refresh_token()
        action_id = await self.hass.async_add_executor_job(
            self.vehicle_manager.start_valet_mode, vehicle_id
        )
        self.hass.async_create_task(
            self.async_await_action_and_refresh(vehicle_id, action_id)
        )

    async def async_stop_valet_mode(self, vehicle_id: str):
        await self.async_check_and_refresh_token()
        action_id = await self.hass.async_add_executor_job(
            self.vehicle_manager.stop_valet_mode,
            vehicle_id,
        )
        self.hass.async_create_task(
            self.async_await_action_and_refresh(vehicle_id, action_id)
        )

    async def async_set_v2l_limit(self, vehicle_id: str, limit: int):
        await self.async_check_and_refresh_token()
        action_id = await self.hass.async_add_executor_job(
            self.vehicle_manager.set_vehicle_to_load_discharge_limit, vehicle_id, limit
        )
        self.hass.async_create_task(
            self.async_await_action_and_refresh(vehicle_id, action_id)
        )

    async def async_set_windows(
        self, vehicle_id: str, windowOptions: WindowRequestOptions
    ):
        await self.async_check_and_refresh_token()
        action_id = await self.hass.async_add_executor_job(
            self.vehicle_manager.set_windows_state, vehicle_id, windowOptions
        )
        self.hass.async_create_task(
            self.async_await_action_and_refresh(vehicle_id, action_id)
        )
