#!/usr/bin/env python3
# Auto-generated classes based on your _types.go file (with special logic for CRDs that embed metav1.ObjectMeta)
# The change on this file will be overwritten by running edabuilder create or generate.
import eda_common as eda

from . import Metadata, Y_NAME

from .constants import *
Y_POLLINTERVALSECONDS = 'pollIntervalSeconds'
Y_RETENTIONMONTHS = 'retentionMonths'
Y_HEALTH = 'health'
Y_MESSAGE = 'message'
Y_LASTPOLLTIME = 'lastPollTime'
Y_LASTTRANSACTIONID = 'lastTransactionId'
Y_LASTUSEREVENTMS = 'lastUserEventMs'
Y_TRANSACTIONSPROCESSED = 'transactionsProcessed'
Y_KCEVENTSPROCESSED = 'kcEventsProcessed'
Y_LOGFILES = 'logFiles'
Y_SUBSYSTEMS = 'subsystems'
Y_VERSION = 'version'
Y_SIZEBYTES = 'sizeBytes'
Y_EDAAPI = 'edaApi'
Y_KEYCLOAKEVENTS = 'keycloakEvents'
# Package objects (GVK Schemas)
USERAUDITCONFIG_SCHEMA = eda.Schema(group='useraudit.eda.edacommunity.com', version='v1alpha1', kind='UserAuditConfig')


class LogFileInfo:
    def __init__(
        self,
        name: str,
        sizeBytes: int,
    ):
        self.name = name
        self.sizeBytes = sizeBytes

    def to_input(self):  # pragma: no cover
        _rval = {}
        if self.name is not None:
            _rval[Y_NAME] = self.name
        if self.sizeBytes is not None:
            _rval[Y_SIZEBYTES] = self.sizeBytes
        return _rval

    @staticmethod
    def from_input(obj) -> 'LogFileInfo | None':
        if obj:
            _name = obj.get(Y_NAME)
            _sizeBytes = obj.get(Y_SIZEBYTES)
            return LogFileInfo(
                name=_name,
                sizeBytes=_sizeBytes,
            )
        return None  # pragma: no cover


class SubsystemHealth:
    def __init__(
        self,
        edaApi: str | None = None,
        keycloakEvents: str | None = None,
    ):
        self.edaApi = edaApi
        self.keycloakEvents = keycloakEvents

    def to_input(self):  # pragma: no cover
        _rval = {}
        if self.edaApi is not None:
            _rval[Y_EDAAPI] = self.edaApi
        if self.keycloakEvents is not None:
            _rval[Y_KEYCLOAKEVENTS] = self.keycloakEvents
        return _rval

    @staticmethod
    def from_input(obj) -> 'SubsystemHealth | None':
        if obj:
            _edaApi = obj.get(Y_EDAAPI)
            _keycloakEvents = obj.get(Y_KEYCLOAKEVENTS)
            return SubsystemHealth(
                edaApi=_edaApi,
                keycloakEvents=_keycloakEvents,
            )
        return None  # pragma: no cover


class UserAuditConfigSpec:
    def __init__(
        self,
        pollIntervalSeconds: int | None = None,
        retentionMonths: int | None = None,
    ):
        self.pollIntervalSeconds = pollIntervalSeconds
        self.retentionMonths = retentionMonths

    def to_input(self):  # pragma: no cover
        _rval = {}
        if self.pollIntervalSeconds is not None:
            _rval[Y_POLLINTERVALSECONDS] = self.pollIntervalSeconds
        if self.retentionMonths is not None:
            _rval[Y_RETENTIONMONTHS] = self.retentionMonths
        return _rval

    @staticmethod
    def from_input(obj) -> 'UserAuditConfigSpec | None':
        if obj:
            _pollIntervalSeconds = obj.get(Y_POLLINTERVALSECONDS, 300)
            _retentionMonths = obj.get(Y_RETENTIONMONTHS, 0)
            return UserAuditConfigSpec(
                pollIntervalSeconds=_pollIntervalSeconds,
                retentionMonths=_retentionMonths,
            )
        return None  # pragma: no cover


class UserAuditConfigStatus:
    def __init__(
        self,
        health: str | None = None,
        message: str | None = None,
        lastPollTime: str | None = None,
        lastTransactionId: int | None = None,
        lastUserEventMs: int | None = None,
        transactionsProcessed: int | None = None,
        kcEventsProcessed: int | None = None,
        logFiles: list[LogFileInfo] | None = None,
        subsystems: SubsystemHealth | None = None,
        version: str | None = None,
    ):
        self.health = health
        self.message = message
        self.lastPollTime = lastPollTime
        self.lastTransactionId = lastTransactionId
        self.lastUserEventMs = lastUserEventMs
        self.transactionsProcessed = transactionsProcessed
        self.kcEventsProcessed = kcEventsProcessed
        self.logFiles = logFiles
        self.subsystems = subsystems
        self.version = version

    def to_input(self):  # pragma: no cover
        _rval = {}
        if self.health is not None:
            _rval[Y_HEALTH] = self.health
        if self.message is not None:
            _rval[Y_MESSAGE] = self.message
        if self.lastPollTime is not None:
            _rval[Y_LASTPOLLTIME] = self.lastPollTime
        if self.lastTransactionId is not None:
            _rval[Y_LASTTRANSACTIONID] = self.lastTransactionId
        if self.lastUserEventMs is not None:
            _rval[Y_LASTUSEREVENTMS] = self.lastUserEventMs
        if self.transactionsProcessed is not None:
            _rval[Y_TRANSACTIONSPROCESSED] = self.transactionsProcessed
        if self.kcEventsProcessed is not None:
            _rval[Y_KCEVENTSPROCESSED] = self.kcEventsProcessed
        if self.logFiles is not None:
            _rval[Y_LOGFILES] = [x.to_input() for x in self.logFiles]
        if self.subsystems is not None:
            _rval[Y_SUBSYSTEMS] = self.subsystems.to_input()
        if self.version is not None:
            _rval[Y_VERSION] = self.version
        return _rval

    @staticmethod
    def from_input(obj) -> 'UserAuditConfigStatus | None':
        if obj:
            _health = obj.get(Y_HEALTH)
            _message = obj.get(Y_MESSAGE)
            _lastPollTime = obj.get(Y_LASTPOLLTIME)
            _lastTransactionId = obj.get(Y_LASTTRANSACTIONID)
            _lastUserEventMs = obj.get(Y_LASTUSEREVENTMS)
            _transactionsProcessed = obj.get(Y_TRANSACTIONSPROCESSED)
            _kcEventsProcessed = obj.get(Y_KCEVENTSPROCESSED)
            _logFiles = []
            if obj.get(Y_LOGFILES) is not None:
                for x in obj.get(Y_LOGFILES):
                    _logFiles.append(LogFileInfo.from_input(x))
            _subsystems = SubsystemHealth.from_input(obj.get(Y_SUBSYSTEMS))
            _version = obj.get(Y_VERSION)
            return UserAuditConfigStatus(
                health=_health,
                message=_message,
                lastPollTime=_lastPollTime,
                lastTransactionId=_lastTransactionId,
                lastUserEventMs=_lastUserEventMs,
                transactionsProcessed=_transactionsProcessed,
                kcEventsProcessed=_kcEventsProcessed,
                logFiles=_logFiles,
                subsystems=_subsystems,
                version=_version,
            )
        return None  # pragma: no cover


class UserAuditConfig:
    def __init__(
        self,
        metadata: Metadata | None = None,
        spec: UserAuditConfigSpec | None = None,
        status: UserAuditConfigStatus | None = None
    ):
        self.metadata = metadata
        self.spec = spec
        self.status = status

    def to_input(self):  # pragma: no cover
        _rval = {}
        _rval[Y_SCHEMA_KEY] = USERAUDITCONFIG_SCHEMA
        if self.metadata is not None:
            _rval[Y_NAME] = self.metadata.name
        if self.spec is not None:
            _rval[Y_SPEC] = self.spec.to_input()
        if self.status is not None:
            _rval[Y_STATUS] = self.status.to_input()
        return _rval

    @staticmethod
    def from_input(obj) -> 'UserAuditConfig | None':
        if obj:
            _metadata = (
                Metadata.from_input(obj.get(Y_METADATA))
                if obj.get(Y_METADATA, None)
                else Metadata.from_name(obj.get(Y_NAME))
            )
            _spec = UserAuditConfigSpec.from_input(obj.get(Y_SPEC, None))
            _status = UserAuditConfigStatus.from_input(obj.get(Y_STATUS))
            return UserAuditConfig(
                metadata=_metadata,
                spec=_spec,
                status=_status,
            )
        return None  # pragma: no cover


class UserAuditConfigList:
    def __init__(
        self,
        items: list[UserAuditConfig],
        listMeta: object | None = None
    ):
        self.items = items
        self.listMeta = listMeta

    def to_input(self):  # pragma: no cover
        _rval = {}
        if self.items is not None:
            _rval[Y_ITEMS] = self.items
        if self.listMeta is not None:
            _rval[Y_METADATA] = self.listMeta
        return _rval

    @staticmethod
    def from_input(obj) -> 'UserAuditConfigList | None':
        if obj:
            _items = obj.get(Y_ITEMS, [])
            _listMeta = obj.get(Y_METADATA, None)
            return UserAuditConfigList(
                items=_items,
                listMeta=_listMeta,
            )
        return None  # pragma: no cover
