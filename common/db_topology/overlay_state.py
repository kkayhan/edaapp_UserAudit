#!/usr/bin/env python3
from .constants import DB_TOPO_ATTRIBUTES


class DbTopoOverlayState:
    def __init__(self,
                 db_value,):
        self.db_value = db_value

    def set_metadata(self,
                     ui_name: str,
                     ui_description: str,):
        self.db_value['ui_name'] = ui_name
        self.db_value['ui_description'] = ui_description
        return self

    def set_metadata_i18n(self,
                          ui_name_key: str,
                          ui_description_key: str,):
        self.db_value['ui_name_key'] = ui_name_key
        self.db_value['ui_description_key'] = ui_description_key
        return self


class DbTopoOverlayAttrMetadata:
    def __init__(self,
                 db_value,):
        self.db_value = db_value

    def set_metadata(self,
                     ui_name: str,
                     ui_description: str,):
        self.db_value['ui_name'] = ui_name
        self.db_value['ui_description'] = ui_description
        return self

    def set_metadata_i18n(self,
                          ui_name_key: str,
                          ui_description_key: str,):
        self.db_value['ui_name_key'] = ui_name_key
        self.db_value['ui_description_key'] = ui_description_key
        return self


class DbTopoOverlayAttrsQuery:
    def __init__(self,
                 db_value,):
        self.db_value = db_value

    def add_attribute(self,
                      attr: str,):
        if DB_TOPO_ATTRIBUTES not in self.db_value:
            self.db_value[DB_TOPO_ATTRIBUTES] = {}
        self.db_value[DB_TOPO_ATTRIBUTES][attr] = {}
        return DbTopoOverlayAttrMetadata(self.db_value[DB_TOPO_ATTRIBUTES][attr])
