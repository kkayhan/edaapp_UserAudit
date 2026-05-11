#!/usr/bin/env python3
# Auto-generated classes based on your _types.go file (with special logic for CRDs that embed metav1.ObjectMeta)
# The change on this file will be overwritten by running edabuilder create or generate.
import eda_common as eda

from . import Metadata, Y_NAME

from common.api.v1alpha1.pysrc.constants import *
Y_IPPREFIX = 'ipPrefix'
Y_PRIMARY = 'primary'


class IPAddress:
    def __init__(
        self,
        ipPrefix: str,
        primary: bool | None = None,
    ):
        self.ipPrefix = ipPrefix
        self.primary = primary

    def to_input(self):  # pragma: no cover
        _rval = {}
        if self.ipPrefix is not None:
            _rval[Y_IPPREFIX] = self.ipPrefix
        if self.primary is not None:
            _rval[Y_PRIMARY] = self.primary
        return _rval

    @staticmethod
    def from_input(obj) -> 'IPAddress | None':
        if obj:
            _ipPrefix = obj.get(Y_IPPREFIX)
            _primary = obj.get(Y_PRIMARY)
            return IPAddress(
                ipPrefix=_ipPrefix,
                primary=_primary,
            )
        return None  # pragma: no cover
