"""
Z-Wave Command Classes Dictionary
Next Generation Z-Wave Security Testing Tool

Original Z-Attack developed by Advens (2015)
https://github.com/Advens/Z-Attack

Refactored and Enhanced by Penthertz (2025)
- Complete code modernization and restructuring
- Modular architecture with separated GUI and logic
- Added S2 (Security 2) support
- Enhanced UI with ImGui
- Modern argument parsing
- Improved error handling and stability

Website: https://penthertz.com
License: GPLv3

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program comes with ABSOLUTELY NO WARRANTY.
"""


ZwaveClass = {
    # ==================== SECURITY ====================
    "98": {
        "name": "SecurityCmd",
        "80": "SecurityCmd_SupportedGet",
        "81": "SecurityCmd_SupportedReport",
        "02": "SecurityCmd_SchemeGet",
        "03": "SecurityCmd_SchemeReport",
        "04": "SecurityCmd_NetworkKeySet",
        "05": "SecurityCmd_NetworkKeyVerify",
        "06": "SecurityCmd_SchemeInherit",
        "40": "SecurityCmd_NonceGet",
        "80": "SecurityCmd_NonceReport",
        "81": "SecurityCmd_MessageEncap",
        "c1": "SecurityCmd_MessageEncapNonceGet"
    },
    
    # ==================== SECURITY 2 (S2) ====================
    "9f": {
        "name": "Security2Cmd",
        "01": "Security2Cmd_NonceGet",
        "02": "Security2Cmd_NonceReport",
        "03": "Security2Cmd_MessageEncap",
        "04": "Security2Cmd_KexGet",
        "05": "Security2Cmd_KexReport",
        "06": "Security2Cmd_KexSet",
        "07": "Security2Cmd_KexFail",
        "08": "Security2Cmd_PublicKeyReport",
        "09": "Security2Cmd_NetworkKeyGet",
        "0a": "Security2Cmd_NetworkKeyReport",
        "0b": "Security2Cmd_NetworkKeyVerify",
        "0c": "Security2Cmd_TransferEnd",
        "11": "Security2Cmd_CommandsSupportedGet",
        "12": "Security2Cmd_CommandsSupportedReport"
    },
    
    # ==================== BASIC ====================
    "20": {
        "name": "BasicCmd",
        "01": "BasicCmd_Set",
        "02": "BasicCmd_Get",
        "03": "BasicCmd_Report"
    },
    
    # ==================== SWITCH BINARY ====================
    "25": {
        "name": "SwitchBinaryCmd",
        "01": "SwitchBinaryCmd_Set",
        "02": "SwitchBinaryCmd_Get",
        "03": "SwitchBinaryCmd_Report"
    },
    
    # ==================== SWITCH MULTILEVEL ====================
    "26": {
        "name": "SwitchMultilevelCmd",
        "01": "SwitchMultilevelCmd_Set",
        "02": "SwitchMultilevelCmd_Get",
        "03": "SwitchMultilevelCmd_Report",
        "04": "SwitchMultilevelCmd_StartLevelChange",
        "05": "SwitchMultilevelCmd_StopLevelChange",
        "06": "SwitchMultilevelCmd_SupportedGet",
        "07": "SwitchMultilevelCmd_SupportedReport"
    },
    
    # ==================== SWITCH ALL ====================
    "27": {
        "name": "SwitchAllCmd",
        "01": "SwitchAllCmd_Set",
        "02": "SwitchAllCmd_Get",
        "03": "SwitchAllCmd_Report",
        "04": "SwitchAllCmd_On",
        "05": "SwitchAllCmd_Off"
    },
    
    # ==================== SENSOR BINARY ====================
    "30": {
        "name": "SensorBinaryCmd",
        "01": "SensorBinaryCmd_SupportedGet",
        "02": "SensorBinaryCmd_Get",
        "03": "SensorBinaryCmd_Report",
        "04": "SensorBinaryCmd_SupportedSensorReport"
    },
    
    # ==================== SENSOR MULTILEVEL ====================
    "31": {
        "name": "SensorMultilevelCmd",
        "01": "SensorMultilevelCmd_SupportedGet",
        "02": "SensorMultilevelCmd_SupportedReport",
        "04": "SensorMultilevelCmd_Get",
        "05": "SensorMultilevelCmd_Report",
        "06": "SensorMultilevelCmd_SupportedScaleGet",
        "07": "SensorMultilevelCmd_SupportedScaleReport"
    },
    
    # ==================== METER ====================
    "32": {
        "name": "MeterCmd",
        "01": "MeterCmd_Get",
        "02": "MeterCmd_Report",
        "03": "MeterCmd_SupportedGet",
        "04": "MeterCmd_SupportedReport",
        "05": "MeterCmd_Reset"
    },
    
    # ==================== COLOR CONTROL ====================
    "33": {
        "name": "ColorControlCmd",
        "01": "ColorControlCmd_CapabilityGet",
        "02": "ColorControlCmd_CapabilityReport",
        "03": "ColorControlCmd_Get",
        "04": "ColorControlCmd_Report",
        "05": "ColorControlCmd_Set",
        "06": "ColorControlCmd_StartColorChange",
        "07": "ColorControlCmd_StopColorChange"
    },
    
    # ==================== THERMOSTAT MODE ====================
    "40": {
        "name": "ThermostatModeCmd",
        "01": "ThermostatModeCmd_Set",
        "02": "ThermostatModeCmd_Get",
        "03": "ThermostatModeCmd_Report",
        "04": "ThermostatModeCmd_SupportedGet",
        "05": "ThermostatModeCmd_SupportedReport"
    },
    
    # ==================== THERMOSTAT SETPOINT ====================
    "43": {
        "name": "ThermostatSetpointCmd",
        "01": "ThermostatSetpointCmd_Set",
        "02": "ThermostatSetpointCmd_Get",
        "03": "ThermostatSetpointCmd_Report",
        "04": "ThermostatSetpointCmd_SupportedGet",
        "05": "ThermostatSetpointCmd_SupportedReport",
        "09": "ThermostatSetpointCmd_CapabilitiesGet",
        "0a": "ThermostatSetpointCmd_CapabilitiesReport"
    },
    
    # ==================== THERMOSTAT FAN MODE ====================
    "44": {
        "name": "ThermostatFanModeCmd",
        "01": "ThermostatFanModeCmd_Set",
        "02": "ThermostatFanModeCmd_Get",
        "03": "ThermostatFanModeCmd_Report",
        "04": "ThermostatFanModeCmd_SupportedGet",
        "05": "ThermostatFanModeCmd_SupportedReport"
    },
    
    # ==================== THERMOSTAT FAN STATE ====================
    "45": {
        "name": "ThermostatFanStateCmd",
        "02": "ThermostatFanStateCmd_Get",
        "03": "ThermostatFanStateCmd_Report"
    },
    
    # ==================== DOOR LOCK ====================
    "62": {
        "name": "DoorLockCmd",
        "01": "DoorLockCmd_Set",
        "02": "DoorLockCmd_Get",
        "03": "DoorLockCmd_Report",
        "04": "DoorLockCmd_ConfigurationSet",
        "05": "DoorLockCmd_ConfigurationGet",
        "06": "DoorLockCmd_ConfigurationReport"
    },
    
    # ==================== USER CODE ====================
    "63": {
        "name": "UserCodeCmd",
        "01": "UserCodeCmd_Set",
        "02": "UserCodeCmd_Get",
        "03": "UserCodeCmd_Report",
        "04": "UserCodeCmd_UsersNumberGet",
        "05": "UserCodeCmd_UsersNumberReport"
    },
    
    # ==================== BARRIER OPERATOR ====================
    "66": {
        "name": "BarrierOperatorCmd",
        "01": "BarrierOperatorCmd_Set",
        "02": "BarrierOperatorCmd_Get",
        "03": "BarrierOperatorCmd_Report",
        "04": "BarrierOperatorCmd_SignalingCapabilitiesGet",
        "05": "BarrierOperatorCmd_SignalingCapabilitiesReport",
        "06": "BarrierOperatorCmd_EventSignalingSet",
        "07": "BarrierOperatorCmd_EventSignalingGet",
        "08": "BarrierOperatorCmd_EventSignalingReport"
    },
    
    # ==================== CONFIGURATION ====================
    "70": {
        "name": "ConfigurationCmd",
        "04": "ConfigurationCmd_Set",
        "05": "ConfigurationCmd_Get",
        "06": "ConfigurationCmd_Report",
        "07": "ConfigurationCmd_BulkSet",
        "08": "ConfigurationCmd_BulkGet",
        "09": "ConfigurationCmd_BulkReport",
        "0d": "ConfigurationCmd_NameGet",
        "0e": "ConfigurationCmd_NameReport",
        "0f": "ConfigurationCmd_InfoGet",
        "10": "ConfigurationCmd_InfoReport",
        "11": "ConfigurationCmd_PropertiesGet",
        "12": "ConfigurationCmd_PropertiesReport"
    },
    
    # ==================== ALARM / NOTIFICATION ====================
    "71": {
        "name": "NotificationCmd",
        "01": "NotificationCmd_EventSupportedGet",
        "02": "NotificationCmd_EventSupportedReport",
        "04": "NotificationCmd_Get",
        "05": "NotificationCmd_Report",
        "06": "NotificationCmd_Set",
        "07": "NotificationCmd_SupportedGet",
        "08": "NotificationCmd_SupportedReport"
    },
    
    # ==================== MANUFACTURER SPECIFIC ====================
    "72": {
        "name": "ManufacturerSpecificCmd",
        "04": "ManufacturerSpecificCmd_Get",
        "05": "ManufacturerSpecificCmd_Report",
        "06": "ManufacturerSpecificCmd_DeviceSpecificGet",
        "07": "ManufacturerSpecificCmd_DeviceSpecificReport"
    },
    
    # ==================== POWERLEVEL ====================
    "73": {
        "name": "PowerlevelCmd",
        "01": "PowerlevelCmd_Set",
        "02": "PowerlevelCmd_Get",
        "03": "PowerlevelCmd_Report",
        "04": "PowerlevelCmd_TestNodeSet",
        "05": "PowerlevelCmd_TestNodeGet",
        "06": "PowerlevelCmd_TestNodeReport"
    },
    
    # ==================== PROTECTION ====================
    "75": {
        "name": "ProtectionCmd",
        "01": "ProtectionCmd_Set",
        "02": "ProtectionCmd_Get",
        "03": "ProtectionCmd_Report",
        "04": "ProtectionCmd_SupportedGet",
        "05": "ProtectionCmd_SupportedReport",
        "06": "ProtectionCmd_ExclusiveControlSet",
        "07": "ProtectionCmd_ExclusiveControlGet",
        "08": "ProtectionCmd_ExclusiveControlReport",
        "09": "ProtectionCmd_TimeoutSet",
        "0a": "ProtectionCmd_TimeoutGet",
        "0b": "ProtectionCmd_TimeoutReport"
    },
    
    # ==================== LOCK ====================
    "76": {
        "name": "LockCmd",
        "01": "LockCmd_Set",
        "02": "LockCmd_Get",
        "03": "LockCmd_Report"
    },
    
    # ==================== NODE NAMING ====================
    "77": {
        "name": "NodeNamingCmd",
        "01": "NodeNamingCmd_Set",
        "02": "NodeNamingCmd_Get",
        "03": "NodeNamingCmd_Report",
        "04": "NodeNamingCmd_LocationSet",
        "05": "NodeNamingCmd_LocationGet",
        "06": "NodeNamingCmd_LocationReport"
    },
    
    # ==================== FIRMWARE UPDATE ====================
    "7a": {
        "name": "FirmwareUpdateCmd",
        "01": "FirmwareUpdateCmd_RequestGet",
        "02": "FirmwareUpdateCmd_RequestReport",
        "03": "FirmwareUpdateCmd_Get",
        "04": "FirmwareUpdateCmd_Report",
        "05": "FirmwareUpdateCmd_StatusReport",
        "06": "FirmwareUpdateCmd_ActivationSet",
        "07": "FirmwareUpdateCmd_ActivationReport"
    },
    
    # ==================== ASSOCIATION GROUP INFO ====================
    "59": {
        "name": "AssociationGrpInfoCmd",
        "01": "AssociationGrpInfoCmd_NameGet",
        "02": "AssociationGrpInfoCmd_NameReport",
        "03": "AssociationGrpInfoCmd_InfoGet",
        "04": "AssociationGrpInfoCmd_InfoReport",
        "05": "AssociationGrpInfoCmd_ListGet",
        "06": "AssociationGrpInfoCmd_ListReport",
        "07": "AssociationGrpInfoCmd_CommandListGet",
        "08": "AssociationGrpInfoCmd_CommandListReport"
    },
    
    # ==================== DEVICE RESET LOCALLY ====================
    "5a": {
        "name": "DeviceResetLocallyCmd",
        "01": "DeviceResetLocallyCmd_Notification"
    },
    
    # ==================== CENTRAL SCENE ====================
    "5b": {
        "name": "CentralSceneCmd",
        "01": "CentralSceneCmd_SupportedGet",
        "02": "CentralSceneCmd_SupportedReport",
        "03": "CentralSceneCmd_Notification",
        "04": "CentralSceneCmd_ConfigurationSet",
        "05": "CentralSceneCmd_ConfigurationGet",
        "06": "CentralSceneCmd_ConfigurationReport"
    },
    
    # ==================== BATTERY ====================
    "80": {
        "name": "BatteryCmd",
        "02": "BatteryCmd_Get",
        "03": "BatteryCmd_Report",
        "04": "BatteryCmd_HealthGet",
        "05": "BatteryCmd_HealthReport"
    },
    
    # ==================== WAKE UP ====================
    "84": {
        "name": "WakeUpCmd",
        "04": "WakeUpCmd_IntervalSet",
        "05": "WakeUpCmd_IntervalGet",
        "06": "WakeUpCmd_IntervalReport",
        "07": "WakeUpCmd_Notification",
        "08": "WakeUpCmd_NoMoreInformation",
        "09": "WakeUpCmd_IntervalCapabilitiesGet",
        "0a": "WakeUpCmd_IntervalCapabilitiesReport"
    },
    
    # ==================== ASSOCIATION ====================
    "85": {
        "name": "AssociationCmd",
        "01": "AssociationCmd_Set",
        "02": "AssociationCmd_Get",
        "03": "AssociationCmd_Report",
        "04": "AssociationCmd_Remove",
        "05": "AssociationCmd_GroupingsGet",
        "06": "AssociationCmd_GroupingsReport",
        "0b": "AssociationCmd_SpecificGroupGet",
        "0c": "AssociationCmd_SpecificGroupReport"
    },
    
    # ==================== VERSION ====================
    "86": {
        "name": "VersionCmd",
        "11": "VersionCmd_Get",
        "12": "VersionCmd_Report",
        "13": "VersionCmd_CommandClassGet",
        "14": "VersionCmd_CommandClassReport",
        "15": "VersionCmd_CapabilitiesGet",
        "16": "VersionCmd_CapabilitiesReport",
        "17": "VersionCmd_ZWaveSoftwareGet",
        "18": "VersionCmd_ZWaveSoftwareReport"
    },
    
    # ==================== INDICATOR ====================
    "87": {
        "name": "IndicatorCmd",
        "01": "IndicatorCmd_Set",
        "02": "IndicatorCmd_Get",
        "03": "IndicatorCmd_Report",
        "04": "IndicatorCmd_SupportedGet",
        "05": "IndicatorCmd_SupportedReport"
    },
    
    # ==================== MULTI CHANNEL ====================
    "60": {
        "name": "MultiChannelCmd",
        "07": "MultiChannelCmd_EndPointGet",
        "08": "MultiChannelCmd_EndPointReport",
        "09": "MultiChannelCmd_CapabilityGet",
        "0a": "MultiChannelCmd_CapabilityReport",
        "0b": "MultiChannelCmd_EndPointFind",
        "0c": "MultiChannelCmd_EndPointFindReport",
        "0d": "MultiChannelCmd_CmdEncap",
        "0e": "MultiChannelCmd_AggregatedMembersGet",
        "0f": "MultiChannelCmd_AggregatedMembersReport"
    },
    
    # ==================== MULTI CHANNEL ASSOCIATION ====================
    "8e": {
        "name": "MultiChannelAssociationCmd",
        "01": "MultiChannelAssociationCmd_Set",
        "02": "MultiChannelAssociationCmd_Get",
        "03": "MultiChannelAssociationCmd_Report",
        "04": "MultiChannelAssociationCmd_Remove",
        "05": "MultiChannelAssociationCmd_GroupingsGet",
        "06": "MultiChannelAssociationCmd_GroupingsReport"
    },
    
    # ==================== CLOCK ====================
    "81": {
        "name": "ClockCmd",
        "04": "ClockCmd_Set",
        "05": "ClockCmd_Get",
        "06": "ClockCmd_Report"
    },
    
    # ==================== TIME PARAMETERS ====================
    "8b": {
        "name": "TimeParametersCmd",
        "01": "TimeParametersCmd_Set",
        "02": "TimeParametersCmd_Get",
        "03": "TimeParametersCmd_Report"
    },
    
    # ==================== SCHEDULE ====================
    "53": {
        "name": "ScheduleCmd",
        "01": "ScheduleCmd_SupportedGet",
        "02": "ScheduleCmd_SupportedReport",
        "03": "ScheduleCmd_Set",
        "04": "ScheduleCmd_Get",
        "05": "ScheduleCmd_Report",
        "06": "ScheduleCmd_Remove",
        "07": "ScheduleCmd_StateSet",
        "08": "ScheduleCmd_StateGet",
        "09": "ScheduleCmd_StateReport"
    },
    
    # ==================== WINDOW COVERING ====================
    "6a": {
        "name": "WindowCoveringCmd",
        "01": "WindowCoveringCmd_SupportedGet",
        "02": "WindowCoveringCmd_SupportedReport",
        "03": "WindowCoveringCmd_Get",
        "04": "WindowCoveringCmd_Report",
        "05": "WindowCoveringCmd_Set",
        "06": "WindowCoveringCmd_StartLevelChange",
        "07": "WindowCoveringCmd_StopLevelChange"
    },
    
    # ==================== SOUND SWITCH ====================
    "79": {
        "name": "SoundSwitchCmd",
        "01": "SoundSwitchCmd_TonesNumberGet",
        "02": "SoundSwitchCmd_TonesNumberReport",
        "03": "SoundSwitchCmd_ToneInfoGet",
        "04": "SoundSwitchCmd_ToneInfoReport",
        "05": "SoundSwitchCmd_ConfigurationSet",
        "06": "SoundSwitchCmd_ConfigurationGet",
        "07": "SoundSwitchCmd_ConfigurationReport",
        "08": "SoundSwitchCmd_TonePlaySet",
        "09": "SoundSwitchCmd_TonePlayGet",
        "0a": "SoundSwitchCmd_TonePlayReport"
    },
    
    # ==================== SUPERVISION ====================
    "6c": {
        "name": "SupervisionCmd",
        "01": "SupervisionCmd_Get",
        "02": "SupervisionCmd_Report"
    },
    
    # ==================== TRANSPORT SERVICE ====================
    "55": {
        "name": "TransportServiceCmd",
        "01": "TransportServiceCmd_CommandFirstFragment",
        "02": "TransportServiceCmd_CommandSubsequentFragment",
        "c0": "TransportServiceCmd_CommandSegmentComplete",
        "c1": "TransportServiceCmd_CommandSegmentRequest",
        "c2": "TransportServiceCmd_CommandSegmentWait"
    },
    
    # ==================== ZWAVEPLUS INFO ====================
    "5e": {
        "name": "ZwaveplusInfoCmd",
        "01": "ZwaveplusInfoCmd_Get",
        "02": "ZwaveplusInfoCmd_Report"
    },
    
    # ==================== NETWORK MANAGEMENT INCLUSION ====================
    "34": {
        "name": "NetworkManagementInclusionCmd",
        "01": "NetworkManagementInclusionCmd_FailedNodeRemove",
        "02": "NetworkManagementInclusionCmd_FailedNodeRemoveStatus",
        "03": "NetworkManagementInclusionCmd_NodeAdd",
        "04": "NetworkManagementInclusionCmd_NodeAddStatus",
        "05": "NetworkManagementInclusionCmd_NodeRemove",
        "06": "NetworkManagementInclusionCmd_NodeRemoveStatus",
        "07": "NetworkManagementInclusionCmd_FailedNodeReplace",
        "08": "NetworkManagementInclusionCmd_FailedNodeReplaceStatus",
        "09": "NetworkManagementInclusionCmd_NodeNeighborUpdateRequest",
        "0a": "NetworkManagementInclusionCmd_NodeNeighborUpdateStatus",
        "0b": "NetworkManagementInclusionCmd_ReturnRouteAssign",
        "0c": "NetworkManagementInclusionCmd_ReturnRouteAssignComplete",
        "0d": "NetworkManagementInclusionCmd_ReturnRouteDelete",
        "0e": "NetworkManagementInclusionCmd_ReturnRouteDeleteComplete",
        "11": "NetworkManagementInclusionCmd_NodeAddKeys",
        "12": "NetworkManagementInclusionCmd_NodeAddDskReport",
        "13": "NetworkManagementInclusionCmd_NodeAddSmartStart"
    }
}

# Library Types
LIBRARY = {
    "0": "Unknown",
    "1": "Static Controller",
    "2": "Controller",
    "3": "Enhanced Slave",
    "4": "Slave",
    "5": "Installer",
    "6": "Routing Slave",
    "7": "Bridge Controller",
    "8": "Device Under Test",
    "9": "N/A",
    "10": "AV Remote",
    "11": "AV Device"
}

# S2 Security Classes
S2_SECURITY_CLASSES = {
    "00": "S2 Unauthenticated",
    "01": "S2 Authenticated",
    "02": "S2 Access Control",
    "07": "S0 Legacy"
}

# S2 Key Exchange Schemes
S2_KEX_SCHEMES = {
    "00": "Reserved",
    "01": "KEX_SCHEME_1"
}

# S2 Key Exchange Curves
S2_KEX_CURVES = {
    "00": "Reserved",
    "01": "Curve25519"
}

# Notification Types (Alarm/Notification Command Class)
NOTIFICATION_TYPES = {
    "00": "Unknown",
    "01": "Smoke Alarm",
    "02": "CO Alarm",
    "03": "CO2 Alarm",
    "04": "Heat Alarm",
    "05": "Water Alarm",
    "06": "Access Control",
    "07": "Home Security",
    "08": "Power Management",
    "09": "System",
    "0a": "Emergency Alarm",
    "0b": "Clock",
    "0c": "Appliance",
    "0d": "Home Health",
    "0e": "Siren",
    "0f": "Water Valve",
    "10": "Weather Alarm",
    "11": "Irrigation",
    "12": "Gas Alarm"
}