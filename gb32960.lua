--
-- GB32960 protocol dissector for Wireshark
-- 
-- Author: Ji Bin <matrixji@live.com>
-- License: MIT
--
do
    local debug_level = {
        DISABLED = 0,
        LEVEL_1 = 1,
        LEVEL_2 = 2
    }

    local debug_pref_enum = {{1, "Disabled", debug_level.DISABLED}, {2, "Level 1", debug_level.LEVEL_1},
                             {3, "Level 2", debug_level.LEVEL_2}}

    local default_settings = {
        debug_level = debug_level.LEVEL_2,
        enabled = true,
        port = 19007,
        max_msg_len = 4096
    }

    local proto = Proto('gb32960', 'GB32960')

    -- register preference
    proto.prefs.debug = Pref.enum("Debug", default_settings.debug_level, "The debug printing level", debug_pref_enum)

    -- preference changed callback
    function proto.prefs_changed()
        default_settings.debug_level = proto.prefs.debug
        -- resetDebugLevel()
    end

    -- 命令类型
    local cmd_type_valstr = {
        [1] = "车辆登录",
        [2] = "实时信息上报",
        [3] = "补发信息上报",
        [4] = "车辆登出",
        [5] = "平台登入",
        [6] = "平台登出",
        [7] = "心跳",
        [8] = "终端校时",
        [0x80] = "查询命令",
        [0x81] = "设置命令",
        [0x82] = "车载终端控制命令"
    }

    -- 响应类型
    local resp_type_valstr = {
        [1] = "成功",
        [2] = "错误",
        [3] = "VIN重复",
        [0xfe] = "命令"
    }

    -- 加密类型
    local encryption_type_valstr = {
        [1] = "不加密",
        [2] = "RSA",
        [3] = "AES128",
        [0xfe] = "异常",
        [0xff] = "无效"
    }

    local format_value_as_text = function(val, bytes, offset, div, unit, field)
        local error_value = 0xfe
        local invalid_value = 0xff
        if bytes == 2 then
            error_value = 0xfffe
            invalid_value = 0xffff
        elseif bytes == 4 then
            error_value = 0xfffffffe
            invalid_value = 0xffffffff
        end
        if val == invalid_value then
            field:add_expert_info(PI_MALFORMED, PI_WARN, 'Invalid')
            return '无效'
        elseif val == error_value then
            field:add_expert_info(PI_MALFORMED, PI_WARN, 'Error')
            return '异常'
        end

        local real_value = val + offset
        if div ~= nil and div ~= 1 then
            real_value = real_value * 1.0 / div
            if div == 10 then
                return string.format('%.1f%s', real_value, unit)
            elseif div == 100 then
                return string.format('%.2f%s', real_value, unit)
            elseif div == 1000 then
                return string.format('%.3f%s', real_value, unit)
            elseif div == 10000 then
                return string.format('%.4f%s', real_value, unit)
            elseif div == 100000 then
                return string.format('%.5f%s', real_value, unit)
            else
                return string.format('%.6f%s', real_value, unit)
            end
        else
            return real_value .. unit
        end
    end

    local f = {
        cmd = ProtoField.uint8("gb32960.command", "Command", base.HEX, cmd_type_valstr),
        resp = ProtoField.uint8("gb32960.response", "Response", base.HEX, resp_type_valstr),
        vin = ProtoField.string("gb32960.vin", "VIN", base.UTF_8),
        encrypt = ProtoField.uint8("gb32960.encrypt", "Encrypt", base.HEX, encryption_type_valstr),
        datalen = ProtoField.uint16("gb32960.datalen", "Data Length", base.DEC),
        bcc = ProtoField.uint8("gb32960.bcc", "BCC", base.HEX),
        time_year = ProtoField.uint8("gb32960.datetime.year", "Year", base.DEC),
        time_month = ProtoField.uint8("gb32960.datetime.month", "Month", base.DEC),
        time_day = ProtoField.uint8("gb32960.datetime.day", "Day", base.DEC),
        time_hour = ProtoField.uint8("gb32960.datetime.hour", "Hour", base.DEC),
        time_minute = ProtoField.uint8("gb32960.datetime.minute", "Minute", base.DEC),
        time_second = ProtoField.uint8("gb32960.datetime.second", "Second", base.DEC),

        -- vehicle login
        vehicle_login_serial_number = ProtoField.uint16("gb32960.vehicle_login.serial_number", "Serial Number", base.DEC),
        vehicle_login_iccid = ProtoField.string("gb32960.vehicle_login.iccid", "ICCID", base.UTF_8),
        vehicle_rechargeable_subsystem_count = ProtoField.uint8("gb32960.vehicle_login.rechargeable_subsystem_count",
            "Rechargeable Subsystem Count", base.DEC),
        vehicle_rechargeable_system_codelen = ProtoField.uint8("gb32960.vehicle_login.rechargeable_system_codelen",
            "Rechargeable System Code Length", base.DEC),

        -- realtime data
        realtime_data_type = ProtoField.uint8("gb32960.realtime_data.type", "Data Type", base.HEX, {
            [1] = "整车数据",
            [2] = "驱动电机数据",
            [3] = "燃料电池数据",
            [4] = "发动机数据",
            [5] = "车辆位置数据",
            [6] = "极值数据",
            [7] = "报警数据",
            [8] = "可充电储能装置电压数据",
            [9] = "可充电储能装置温度数据"
        }),

        -- realtime data: vehicle data
        vehicle_data_vehicle_status = ProtoField.uint8("gb32960.realtime_data.vehicle_status.vehicle_status",
            "Vehicle Status", base.HEX, {
                [1] = "启动",
                [2] = "熄火",
                [3] = "其他",
                [0xfe] = "异常",
                [0xff] = "无效"
            }),
        vehicle_data_charge_status = ProtoField.uint8("gb32960.realtime_data.vehicle_status.charge_status",
            "Vehicle Charge Status", base.HEX, {
                [1] = "停车充电",
                [2] = "行驶充电",
                [3] = "未充电",
                [4] = "充电完成",
                [0xfe] = "异常",
                [0xff] = "无效"
            }),
        vehicle_data_run_mode = ProtoField.uint8("gb32960.realtime_data.vehicle_status.run_mode", "Vehicle Run Mode",
            base.HEX, {
                [1] = "纯电",
                [2] = "混动",
                [3] = "燃油",
                [0xfe] = "异常",
                [0xff] = "无效"
            }),
        -- speed * 0.1 as km/h
        vehicle_data_speed = ProtoField.uint16("gb32960.realtime_data.vehicle_status.speed", "Speed", base.DEC),
        vehicle_data_mileage = ProtoField.uint32("gb32960.realtime_data.vehicle_status.mileage", "Mileage", base.DEC),
        vehicle_data_total_voltage = ProtoField.uint16("gb32960.realtime_data.vehicle_status.total_voltage",
            "Total Voltage", base.DEC),
        vehicle_data_total_current = ProtoField.uint16("gb32960.realtime_data.vehicle_status.total_current",
            "Total Current", base.DEC),
        vehicle_data_soc = ProtoField.uint8("gb32960.realtime_data.vehicle_status.soc", "SOC", base.DEC),
        vehicle_data_dc_status = ProtoField.uint8("gb32960.realtime_data.vehicle_status.dc_status", "DC Status",
            base.HEX, {
                [1] = "工作",
                [2] = "断开",
                [0xfe] = "异常",
                [0xff] = "无效"
            }),
        vehicle_data_gear = ProtoField.uint8("gb32960.realtime_data.vehicle_status.gear", "Gear", base.HEX, {
            [1] = "空挡",
            [2] = "停车挡",
            [3] = "驻车挡",
            [4] = "前进挡",
            [5] = "后退挡",
            [0xfe] = "异常",
            [0xff] = "无效"
        }),
        vehicle_data_insulation_resistance = ProtoField.uint16(
            "gb32960.realtime_data.vehicle_status.insulation_resistance", "Insulation Resistance", base.DEC),

        -- realtime data: motor data
        motor_data_count = ProtoField.uint8("gb32960.realtime_data.motor.count", "Motor Count", base.DEC),
        motor_data_motor_seq = ProtoField.uint8("gb32960.realtime_data.motor.seq", "Motor Sequence", base.DEC),
        motor_data_motor_status = ProtoField.uint8("gb32960.realtime_data.motor.status", "Motor Status", base.HEX, {
            [1] = "耗电",
            [2] = "发电",
            [3] = "关闭",
            [4] = "准备",
            [0xfe] = "异常",
            [0xff] = "无效"
        }),
        motor_data_controller_temperature = ProtoField.uint8("gb32960.realtime_data.motor.controller_temperature",
            "Controller Temperature", base.DEC),
        motor_data_rotational_speed = ProtoField.uint16("gb32960.realtime_data.motor.rotational_speed",
            "Rotational Speed", base.DEC),
        motor_data_torque = ProtoField.uint16("gb32960.realtime_data.motor.torque", "Torque", base.DEC),
        motor_data_temperature = ProtoField.uint8("gb32960.realtime_data.motor.temperature", "Temperature", base.DEC),
        motor_data_voltage = ProtoField.uint16("gb32960.realtime_data.motor.voltage", "Voltage", base.DEC),
        motor_data_current = ProtoField.uint16("gb32960.realtime_data.motor.current", "Current", base.DEC),

        -- realtime data: fuel cell data
        fuel_cell_data_battery_voltage = ProtoField.uint16("gb32960.realtime_data.fuel_cell.voltage", "Voltage",
            base.DEC),
        fuel_cell_data_battery_current = ProtoField.uint16("gb32960.realtime_data.fuel_cell.current", "Current",
            base.DEC),
        fuel_cell_data_fuel_consumption = ProtoField.uint16("gb32960.realtime_data.fuel_cell.fuel_consumption",
            "Fuel Consumption", base.DEC),
        fuel_cell_data_probe_temperature_count = ProtoField.uint16(
            "gb32960.realtime_data.fuel_cell.probe_temperature_count", "Probe Temperature Count", base.DEC),
        fuel_cell_data_probe_temperature = ProtoField.uint8("gb32960.realtime_data.fuel_cell.probe_temperature",
            "Probe Temperature", base.DEC),
        fuel_cell_data_hydrogen_system_max_temperature = ProtoField.uint16(
            "gb32960.realtime_data.fuel_cell.hydrogen_system_max_temperature", "Hydrogen System Max Temperature",
            base.DEC),
        fuel_cell_data_hydrogen_system_max_temperature_code = ProtoField.uint8(
            "gb32960.realtime_data.fuel_cell.hydrogen_system_max_temperature_code",
            "Hydrogen System Max Temperature Code", base.DEC),
        fuel_cell_data_hydrogen_system_max_concentration = ProtoField.uint16(
            "gb32960.realtime_data.fuel_cell.hydrogen_system_max_concentration", "Hydrogen System Max Concentration",
            base.DEC),
        fuel_cell_data_hydrogen_system_max_concentration_code = ProtoField.uint8(
            "gb32960.realtime_data.fuel_cell.hydrogen_system_max_concentration_code",
            "Hydrogen System Max Concentration Code", base.DEC),
        fuel_cell_data_hydrogen_system_max_pressure = ProtoField.uint16(
            "gb32960.realtime_data.fuel_cell.hydrogen_system_max_pressure", "Hydrogen System Max Pressure", base.DEC),
        fuel_cell_data_hydrogen_system_max_pressure_code = ProtoField.uint8(
            "gb32960.realtime_data.fuel_cell.hydrogen_system_max_pressure_code", "Hydrogen System Max Pressure Code",
            base.DEC),
        fuel_dc_status = ProtoField.uint8("gb32960.realtime_data.fuel_cell.dc_status", "DC Status", base.HEX, {
            [1] = "工作",
            [2] = "断开",
            [0xfe] = "异常",
            [0xff] = "无效"
        }),
        fuel_cell_data_hydrogen_weight = ProtoField.uint16("gb32960.realtime_data.fuel_cell.hydrogen_weight",
            "Hydrogen Weight", base.DEC),
        -- realtime data: fuel cell data, after GB32960-202x

        -- realtime data: engine data

        -- realtime data: location data
        gps_status = ProtoField.uint8("gb32960.realtime_data.location.gps_status", "GPS Status", base.HEX, {
            [0] = "有效",
            [1] = "无效"
        }, 0x80),
        gps_latitude_direction = ProtoField.uint8("gb32960.realtime_data.location.latitude_direction",
            "Latitude Direction", base.HEX, {
                [0] = "北纬",
                [1] = "南纬"
            }, 0x40),
        gps_longitude_direction = ProtoField.uint8("gb32960.realtime_data.location.longitude_direction",
            "Longitude Direction", base.HEX, {
                [0] = "东经",
                [1] = "西经"
            }, 0x20),

        gps_latitude = ProtoField.uint32("gb32960.realtime_data.location.latitude", "Latitude", base.DEC),
        gps_longitude = ProtoField.uint32("gb32960.realtime_data.location.longitude", "Longitude", base.DEC),

        -- realtime data: extreme data
        extreme_data_max_voltage_subsystem_code = ProtoField.uint8(
            "gb32960.realtime_data.extreme_data.max_voltage_subsystem_code", "Max Voltage Subsystem Code", base.DEC),
        extreme_data_max_voltage_single_code = ProtoField.uint8(
            "gb32960.realtime_data.extreme_data.max_voltage_single_code", "Max Voltage Single Code", base.DEC),
        extreme_data_max_voltage = ProtoField.uint16("gb32960.realtime_data.extreme_data.max_voltage", "Max Voltage",
            base.DEC),
        extreme_data_min_voltage_subsystem_code = ProtoField.uint8(
            "gb32960.realtime_data.extreme_data.min_voltage_subsystem_code", "Min Voltage Subsystem Code", base.DEC),
        extreme_data_min_voltage_single_code = ProtoField.uint8(
            "gb32960.realtime_data.extreme_data.min_voltage_single_code", "Min Voltage Single Code", base.DEC),
        extreme_data_min_voltage = ProtoField.uint16("gb32960.realtime_data.extreme_data.min_voltage", "Min Voltage",
            base.DEC),
        extreme_data_max_temperature_subsystem_code = ProtoField.uint8(
            "gb32960.realtime_data.extreme_data.max_temperature_subsystem_code", "Max Temperature Subsystem Code",
            base.DEC),
        extreme_data_max_temperature_probe_code = ProtoField.uint8(
            "gb32960.realtime_data.extreme_data.max_temperature_probe_code", "Max Temperature Probe Code", base.DEC),
        extreme_data_max_temperature = ProtoField.uint8("gb32960.realtime_data.extreme_data.max_temperature",
            "Max Temperature", base.DEC),
        extreme_data_min_temperature_subsystem_code = ProtoField.uint8(
            "gb32960.realtime_data.extreme_data.min_temperature_subsystem_code", "Min Temperature Subsystem Code",
            base.DEC),
        extreme_data_min_temperature_probe_code = ProtoField.uint8(
            "gb32960.realtime_data.extreme_data.min_temperature_probe_code", "Min Temperature Probe Code", base.DEC),
        extreme_data_min_temperature = ProtoField.uint8("gb32960.realtime_data.extreme_data.min_temperature",
            "Min Temperature", base.DEC),

        -- realtime data: alarm data
        alarm_data_higest_level = ProtoField.uint8("gb32960.realtime_data.alarm_data.higest_level", "Higest Level",
            base.DEC, {
                [0] = "0级",
                [1] = "1级",
                [2] = "2级",
                [3] = "3级",
                [0xfe] = "异常",
                [0xff] = "无效"
            }),

        alarm_flag = ProtoField.uint32("gb32960.realtime_data.alarm_data.flag", "Alarm Flag", base.HEX),
        alarm_flag_temperture = ProtoField.uint32("gb32960.realtime_data.alarm_data.flag_temperture",
            "Alarm Flag  Temperture", base.HEX, {
                [0] = "正常",
                [1] = "温度差异报警"
            }, 0x80000000),
        alarm_flag_battery_high_temperature = ProtoField.uint32(
            "gb32960.realtime_data.alarm_data.flag_battery_high_temperature", "Alarm Flag  Battery High Temperature",
            base.HEX, {
                [0] = "正常",
                [1] = "电池高温报警"
            }, 0x40000000),

        alarm_flag_energy_voltage_over = ProtoField.uint32("gb32960.realtime_data.alarm_data.flag_energy_voltage_over",
            "Alarm Flag  Energy Voltage Over", base.HEX, {
                [0] = "正常",
                [1] = "车载储能装置过压报警"
            }, 0x20000000),
        alarm_flag_energy_voltage_low = ProtoField.uint32("gb32960.realtime_data.alarm_data.flag_energy_voltage_low",
            "Alarm Flag  Energy Voltage Low", base.HEX, {
                [0] = "正常",
                [1] = "车载储能装置欠压报警"
            }, 0x10000000),
        alarm_flag_energy_soc_low = ProtoField.uint32("gb32960.realtime_data.alarm_data.flag_energy_soc_low",
            "Alarm Flag  Energy SOC Low", base.HEX, {
                [0] = "正常",
                [1] = "SOC低报警"
            }, 0x8000000),
        alarm_flag_battery_single_voltage_over = ProtoField.uint32(
            "gb32960.realtime_data.alarm_data.flag_battery_single_voltage_over",
            "Alarm Flag  Battery Single Voltage Over", base.HEX, {
                [0] = "正常",
                [1] = "单体电池过压报警"
            }, 0x4000000),
        alarm_flag_battery_single_voltage_low = ProtoField.uint32(
            "gb32960.realtime_data.alarm_data.flag_battery_single_voltage_low",
            "Alarm Flag  Battery Single Voltage Low", base.HEX, {
                [0] = "正常",
                [1] = "单体电池欠压报警"
            }, 0x2000000),
        alarm_flag_soc_high = ProtoField.uint32("gb32960.realtime_data.alarm_data.flag_soc_high",
            "Alarm Flag  SOC High", base.HEX, {
                [0] = "正常",
                [1] = "SOC过高报警"
            }, 0x1000000),
        alarm_flag_soc_jump = ProtoField.uint32("gb32960.realtime_data.alarm_data.flag_soc_jump",
            "Alarm Flag  SOC Jump", base.HEX, {
                [0] = "正常",
                [1] = "SOC跳变报警"
            }, 0x800000),
        alarm_flag_chargeable_not_match = ProtoField.uint32(
            "gb32960.realtime_data.alarm_data.flag_chargeable_not_match", "Alarm Flag  Chargeable Not Match", base.HEX,
            {
                [0] = "正常",
                [1] = "可充电储能系统不匹配报警"
            }, 0x400000),
        alarm_flag_battery_single_consistency = ProtoField.uint32(
            "gb32960.realtime_data.alarm_data.flag_battery_single_consistency",
            "Alarm Flag  Battery Single Consistency", base.HEX, {
                [0] = "正常",
                [1] = "单体电池一致性差报警"
            }, 0x200000),
        alarm_flag_insulation = ProtoField.uint32("gb32960.realtime_data.alarm_data.flag_insulation",
            "Alarm Flag  Insulation", base.HEX, {
                [0] = "正常",
                [1] = "绝缘报警"
            }, 0x100000),
        alarm_flag_dcdc_temperature = ProtoField.uint32("gb32960.realtime_data.alarm_data.flag_dcdc_temperature",
            "Alarm Flag  DCDC Temperature", base.HEX, {
                [0] = "正常",
                [1] = "DCDC温度报警"
            }, 0x80000),
        alarm_flag_brake_system = ProtoField.uint32("gb32960.realtime_data.alarm_data.flag_brake_system",
            "Alarm Flag  Brake System", base.HEX, {
                [0] = "正常",
                [1] = "制动系统报警"
            }, 0x40000),

        alarm_flag_dcdc_status = ProtoField.uint32("gb32960.realtime_data.alarm_data.flag_dcdc_status",
            "Alarm Flag  DCDC Status", base.HEX, {
                [0] = "正常",
                [1] = "DCDC状态报警"
            }, 0x20000),

        alarm_flag_motor_controller_temperature = ProtoField.uint32(
            "gb32960.realtime_data.alarm_data.flag_motor_controller_temperature",
            "Alarm Flag  Motor Controller Temperature", base.HEX, {
                [0] = "正常",
                [1] = "驱动电机控制器温度报警"
            }, 0x10000),

        alarm_flag_high_voltage_interlock_status = ProtoField.uint32(
            "gb32960.realtime_data.alarm_data.flag_high_voltage_interlock_status",
            "Alarm Flag  High Voltage Interlock Status", base.HEX, {
                [0] = "正常",
                [1] = "高压互锁状态报警"
            }, 0x8000),

        alarm_flag_motor_temperature = ProtoField.uint32("gb32960.realtime_data.alarm_data.flag_motor_temperature",
            "Alarm Flag  Motor Temperature", base.HEX, {
                [0] = "正常",
                [1] = "驱动电机温度报警"
            }, 0x4000),

        alarm_flag_energy_type_overcharge = ProtoField.uint32(
            "gb32960.realtime_data.alarm_data.flag_energy_type_overcharge", "Alarm Flag  Energy Type Overcharge",
            base.HEX, {
                [0] = "正常",
                [1] = "车载储能装置类型过充报警"
            }, 0x2000),

        alarm_chargable_alarm_count = ProtoField.uint8("gb32960.realtime_data.alarm_data.chargable_alarm_count",
            "Chargable Alarm Count", base.DEC),
        alarm_chargable_alarm_code = ProtoField.uint32("gb32960.realtime_data.alarm_data.chargable_alarm_code",
            "Chargable Alarm Code", base.HEX),

        alarm_motor_alarm_count = ProtoField.uint8("gb32960.realtime_data.alarm_data.motor_alarm_count",
            "Motor Alarm Count", base.DEC),
        alarm_motor_alarm_code = ProtoField.uint32("gb32960.realtime_data.alarm_data.motor_alarm_code",
            "Motor Alarm Code", base.HEX),
        alarm_engine_alarm_count = ProtoField.uint8("gb32960.realtime_data.alarm_data.engine_alarm_count",
            "Engine Alarm Count", base.DEC),
        alarm_engine_alarm_code = ProtoField.uint32("gb32960.realtime_data.alarm_data.engine_alarm_code",
            "Engine Alarm Code", base.HEX),
        alarm_other_alarm_count = ProtoField.uint8("gb32960.realtime_data.alarm_data.other_alarm_count",
            "Other Alarm Count", base.DEC),
        alarm_other_alarm_code = ProtoField.uint32("gb32960.realtime_data.alarm_data.other_alarm_code",
            "Other Alarm Code", base.HEX),

        -- realtime data: battery voltage
        battery_voltage_pack_count = ProtoField.uint8("gb32960.realtime_data.battery_voltage.pack_count", "Pack Count",
            base.DEC),
        battery_voltage_pack_index = ProtoField.uint8("gb32960.realtime_data.battery_voltage.pack_index", "Pack Index",
            base.DEC),
        battery_voltage_pack_voltage = ProtoField.uint16("gb32960.realtime_data.battery_voltage.pack_voltage",
            "Pack Voltage", base.DEC),
        battery_voltage_pack_current = ProtoField.uint16("gb32960.realtime_data.battery_voltage.pack_current",
            "Pack Current", base.DEC),
        battery_voltage_single_total_count = ProtoField.uint16(
            "gb32960.realtime_data.battery_voltage.single_total_count", "Single Total Count", base.DEC),
        battery_voltage_single_index = ProtoField.uint16("gb32960.realtime_data.battery_voltage.single_index",
            "Single Index", base.DEC),
        battery_voltage_single_count = ProtoField.uint8("gb32960.realtime_data.battery_voltage.single_count",
            "Single Count", base.DEC),
        battery_voltage_single_voltage = ProtoField.uint16("gb32960.realtime_data.battery_voltage.single_voltage",
            "Single Voltage", base.DEC),

        -- realtime data: battery temperature
        battery_temperature_pack_count = ProtoField.uint8("gb32960.realtime_data.battery_temperature.pack_count",
            "Pack Count", base.DEC),
        battery_temperature_pack_index = ProtoField.uint8("gb32960.realtime_data.battery_temperature.pack_index",
            "Pack Index", base.DEC),
        battery_temperature_probe_count = ProtoField.uint8("gb32960.realtime_data.battery_temperature.probe_count",
            "Probe Count", base.DEC),
        battery_temperature_probe = ProtoField.uint8("gb32960.realtime_data.battery_temperature.probe",
            "Probe Temperature", base.DEC)
    }
    proto.fields = f

    local dissect_item_vin = function(buf, pinfo, tree, offset, len)
        local vin = buf(offset, 17):string()
        local vin_item = tree:add(f.vin, buf(offset, 17))
        tree:append_text(', ' .. vin)
        return vin
    end

    local dissect_item_encryption = function(buf, pinfo, tree, offset, len)
        local encryption = buf(offset, 1)
        local encryption_item = tree:add(f.encrypt, encryption)
        local encryption_value = encryption:uint()
        return encryption_value
    end

    local dissect_item_datalen = function(buf, pinfo, tree, offset, len)
        tree:add(f.datalen, buf(offset, 2))
        tree:append_text(', ' .. len .. ' Bytes')
        return len
    end

    local dissect_item_datetime = function(buf, pinfo, root, tree, offset, len)
        local year = buf(offset, 1):uint()
        local month = buf(offset + 1, 1):uint()
        local day = buf(offset + 2, 1):uint()
        local hour = buf(offset + 3, 1):uint()
        local minute = buf(offset + 4, 1):uint()
        local second = buf(offset + 5, 1):uint()
        local datetime_item = tree:add(buf(offset, 6), 'Date Time')
        datetime_item:add(f.time_year, buf(offset, 1))
        datetime_item:add(f.time_month, buf(offset + 1, 1))
        datetime_item:add(f.time_day, buf(offset + 2, 1))
        datetime_item:add(f.time_hour, buf(offset + 3, 1))
        datetime_item:add(f.time_minute, buf(offset + 4, 1))
        datetime_item:add(f.time_second, buf(offset + 5, 1))
        local datetime_string = ', ' .. string.format('%04d-%02d-%02d', year + 2000, month, day)
        datetime_string = datetime_string .. ' ' .. string.format('%02d:%02d:%02d', hour, minute, second)
        datetime_item:append_text(datetime_string)
        tree:append_text(datetime_string)
        root:append_text(datetime_string)
    end

    local dissect_gb32960_single_resp = function(buf, pinfo, tree, offset, len)
        local resp = buf(offset + 2, 1):uint()
        local resp_item = tree:add(f.resp, buf(offset + 2, 1))
        local resp_text = resp_type_valstr[resp] or 'Unknown'
        tree:append_text(', ' .. resp_text)
        local vin = dissect_item_vin(buf, pinfo, tree, offset + 4, len)
        local info_text = string.format('Response(%s) %s', resp_text, vin)
        local enc = dissect_item_encryption(buf, pinfo, tree, offset + 21, len)
        dissect_item_datalen(buf, pinfo, tree, offset + 22, len)
        local data_item = tree:add(buf(offset + 24, len), 'Response Data')
        dissect_item_datetime(buf, pinfo, tree, data_item, offset + 24, len)
        return info_text
    end

    local dissect_gb32960_single_cmd_vehicle_login = function(buf, pinfo, tree, offset, len)
        offset = offset + 24
        local data_item = tree:add(buf(offset, len), 'Vehicle Login Data')
        if len >= 6 then
            dissect_item_datetime(buf, pinfo, tree, data_item, offset, len)
            offset = offset + 6
            len = len - 6
        else
            data_item:add_expert_info(PI_MALFORMED, PI_ERROR, 'Invalid datetime length')
            return
        end

        if len >= 2 then
            data_item:add(f.vehicle_login_serial_number, buf(offset, 2))
            offset = offset + 2
            len = len - 2
        else
            data_item:add_expert_info(PI_MALFORMED, PI_ERROR, 'Invalid serial number length')
            return
        end

        if len >= 20 then
            data_item:add(f.vehicle_login_iccid, buf(offset, 20))
            offset = offset + 20
            len = len - 20
        else
            data_item:add_expert_info(PI_MALFORMED, PI_ERROR, 'Invalid ICCID length')
            return
        end

        if len >= 2 then
            local subsystem_count = buf(offset, 1):uint()
            data_item:add(f.vehicle_rechargeable_subsystem_count, buf(offset, 1))
            offset = offset + 1
            local subsystem_codelen = buf(offset, 1):uint()
            data_item:add(f.vehicle_rechargeable_system_codelen, buf(offset, 1))
            offset = offset + 1
            len = len - 2
        else
            data_item:add_expert_info(PI_MALFORMED, PI_ERROR, 'Invalid rechargeable subsystem count/codelen length')
            return
        end

    end

    local dissect_realtime_data_vehicle_status = function(buf, pinfo, tree, offset, len)
        local vehicle_status = tree:add(buf(offset, 21), 'Vehicle Data(整车数据)')
        vehicle_status:add(f.realtime_data_type, buf(offset, 1))
        vehicle_status:add(f.vehicle_data_vehicle_status, buf(offset + 1, 1))
        vehicle_status:add(f.vehicle_data_charge_status, buf(offset + 2, 1))
        vehicle_status:add(f.vehicle_data_run_mode, buf(offset + 3, 1))
        local speed_item = vehicle_status:add(f.vehicle_data_speed, buf(offset + 4, 2))

        local speed_value = buf(offset + 4, 2):uint()
        local speed_text = format_value_as_text(speed_value, 2, 0, 10, 'km/h', speed_item)
        speed_item:append_text(', ' .. speed_text)

        local mileage_item = vehicle_status:add(f.vehicle_data_mileage, buf(offset + 6, 4))
        local mileage_value = buf(offset + 6, 4):uint()
        local mileage_text = format_value_as_text(mileage_value, 4, 0, 10, 'km', mileage_item)
        mileage_item:append_text(', ' .. mileage_text)

        local voltage_item = vehicle_status:add(f.vehicle_data_total_voltage, buf(offset + 10, 2))
        local voltage_value = buf(offset + 10, 2):uint()
        local voltage_text = format_value_as_text(voltage_value, 2, 0, 10, 'V', voltage_item)
        voltage_item:append_text(', ' .. voltage_text)

        local current_item = vehicle_status:add(f.vehicle_data_total_current, buf(offset + 12, 2))
        local current_value = buf(offset + 12, 2):uint()
        local current_text = format_value_as_text(current_value, 2, 0, 10, 'A', current_item)
        current_item:append_text(', ' .. current_text)

        vehicle_status:add(f.vehicle_data_soc, buf(offset + 14, 1))

        local ir_item = vehicle_status:add(f.vehicle_data_insulation_resistance, buf(offset + 15, 2))
        local ir_value = buf(offset + 15, 2):uint()
        local ir_text = format_value_as_text(ir_value, 2, 0, 1, 'KΩ', ir_item)
        ir_item:append_text(', ' .. ir_text)

        return 21
    end

    local dissect_realtime_data_motor = function(buf, pinfo, tree, offset, len)
        local motor_count = buf(offset + 1, 1):uint()
        local total_bytes = motor_count * 12 + 2

        local motor_data = tree:add(buf(offset, total_bytes), 'Motor Count(驱动电机数据), Count=' .. motor_count)
        for i = 0, motor_count - 1 do
            local motor_seq = buf(offset + 2 + i * 12, 1):uint()
            local motor_item = motor_data:add(buf(offset + 2 + i * 12, 12), 'Motor Sequence=' .. motor_seq)
            motor_item:add(f.motor_data_motor_seq, buf(offset + 2 + i * 12, 1))
            motor_item:add(f.motor_data_motor_status, buf(offset + 3 + i * 12, 1))

            local item = motor_item:add(f.motor_data_controller_temperature, buf(offset + 4 + i * 12, 1))
            local text = format_value_as_text(buf(offset + 4 + i * 12, 1):uint(), 1, -40, 1, '℃', item)
            item:append_text(', ' .. text)

            item = motor_item:add(f.motor_data_rotational_speed, buf(offset + 5 + i * 12, 2))
            text = format_value_as_text(buf(offset + 5 + i * 12, 2):uint(), 2, -20000, 1, 'rpm', item)
            item:append_text(', ' .. text)

            item = motor_item:add(f.motor_data_torque, buf(offset + 7 + i * 12, 2))
            text = format_value_as_text(buf(offset + 7 + i * 12, 2):uint(), 2, -20000, 10, 'Nm', item)
            item:append_text(', ' .. text)

            item = motor_item:add(f.motor_data_temperature, buf(offset + 9 + i * 12, 1))
            text = format_value_as_text(buf(offset + 9 + i * 12, 1):uint(), 1, -40, 1, '℃', item)
            item:append_text(', ' .. text)

            item = motor_item:add(f.motor_data_voltage, buf(offset + 10 + i * 12, 2))
            text = format_value_as_text(buf(offset + 10 + i * 12, 2):uint(), 2, 0, 10, 'V', item)
            item:append_text(', ' .. text)

            item = motor_item:add(f.motor_data_current, buf(offset + 12 + i * 12, 2))
            text = format_value_as_text(buf(offset + 12 + i * 12, 2):uint(), 2, -10000, 10, 'A', item)
            item:append_text(', ' .. text)
        end

        return total_bytes
    end

    local dissect_realtime_data_fuel_cell = function(buf, pinfo, tree, offset, len)
        local probe_count = buf(offset + 7, 2):uint()
        local total_bytes = probe_count * 1 + 8 + 10 + 1
        local fuel_cell_data = tree:add(buf(offset, total_bytes), 'Fuel Cell Data(燃料电池数据)')
        local item = fuel_cell_data:add(f.fuel_cell_data_battery_voltage, buf(offset + 2, 2))
        item:append_text(', ' .. format_value_as_text(buf(offset + 2, 2):uint(), 2, 0, 10, 'V', item))
        item = fuel_cell_data:add(f.fuel_cell_data_battery_current, buf(offset + 4, 2))
        item:append_text(', ' .. format_value_as_text(buf(offset + 4, 2):uint(), 2, 0, 10, 'A', item))
        item = fuel_cell_data:add(f.fuel_cell_data_fuel_consumption, buf(offset + 6, 2))
        item:append_text(', ' .. format_value_as_text(buf(offset + 6, 2):uint(), 2, 0, 100, 'ks/100km', item))
        fuel_cell_data:add(f.fuel_cell_data_probe_temperature_count, buf(offset + 8, 2))
        local probe_count = buf(offset + 8, 2):uint()
        local probe_data = fuel_cell_data:add(buf(offset + 10, probe_count), 'Probe Temperatures: ')
        local temperature_text = ''
        for i = 0, probe_count - 1 do
            local probe_item = probe_data:add(f.fuel_cell_data_probe_temperature, buf(offset + 10 + i, 1))
            local temperature = buf(offset + 10 + i, 1):uint()
            local item_text = format_value_as_text(temperature, 1, -40, 1, '℃', probe_item)
            temperature_text = temperature_text .. item_text
            if i < probe_count - 1 then
                temperature_text = temperature_text .. ', '
            end
            probe_item:append_text(', ' .. item_text .. ', index=' .. i + 1)
        end
        probe_data:append_text(temperature_text)
        offset = offset + 10 + probe_count
        item = fuel_cell_data:add(f.fuel_cell_data_hydrogen_system_max_temperature, buf(offset, 2))
        item:append_text(', ' .. format_value_as_text(buf(offset, 2):uint(), 2, -40, 1, '℃', item))
        fuel_cell_data:add(f.fuel_cell_data_hydrogen_system_max_temperature_code, buf(offset + 2, 1))
        item = fuel_cell_data:add(f.fuel_cell_data_hydrogen_system_max_concentration, buf(offset + 3, 2))
        item:append_text(', ' .. format_value_as_text(buf(offset + 3, 2):uint(), 2, 0, 1, 'mg/kg', item))
        fuel_cell_data:add(f.fuel_cell_data_hydrogen_system_max_concentration_code, buf(offset + 5, 1))
        item = fuel_cell_data:add(f.fuel_cell_data_hydrogen_system_max_pressure, buf(offset + 6, 2))
        item:append_text(', ' .. format_value_as_text(buf(offset + 6, 2):uint(), 2, 0, 10, 'MPa', item))
        fuel_cell_data:add(f.fuel_cell_data_hydrogen_system_max_pressure_code, buf(offset + 8, 1))
        fuel_cell_data:add(f.fuel_dc_status, buf(offset + 9, 1))

        return total_bytes
    end

    local dissect_realtime_data_engine = function(buf, pinfo, tree, offset, len)
        local total_bytes = 6
        local engine_data = tree:add(buf(offset, total_bytes), 'Engine Data(发动机数据)')

        return total_bytes
    end

    local dissect_realtime_data_location = function(buf, pinfo, tree, offset, len)
        local total_bytes = 10
        local location_data = tree:add(buf(offset, total_bytes), 'Location Data(车辆位置数据)')
        location_data:add(f.gps_status, buf(offset + 1, 1))
        location_data:add(f.gps_latitude_direction, buf(offset + 1, 1))
        location_data:add(f.gps_longitude_direction, buf(offset + 1, 1))

        local item = location_data:add(f.gps_latitude, buf(offset + 2, 4))
        item:append_text(', ' .. format_value_as_text(buf(offset + 2, 4):uint(), 4, 0, 1000000, '°', item))
        item = location_data:add(f.gps_longitude, buf(offset + 6, 4))
        item:append_text(', ' .. format_value_as_text(buf(offset + 6, 4):uint(), 4, 0, 1000000, '°', item))

        local gps_status = math.floor(buf(offset + 1, 1):uint() / 0x80) % 2
        if (gps_status == 0) then
            local latitude_direction = math.floor(buf(offset + 1, 1):uint() / 0x40) % 2
            local longitude_direction = math.floor(buf(offset + 1, 1):uint() / 0x20) % 2
            local latitude = buf(offset + 2, 4):uint()
            local longitude = buf(offset + 6, 4):uint()
            local info_text = ', '
            if latitude_direction == 0 then
                info_text = info_text .. '北纬'
            else
                info_text = info_text .. '南纬'
            end
            info_text = info_text .. string.format('%.6f', latitude * 1.0 / 1000000)
            info_text = info_text .. ', '
            if longitude_direction == 0 then
                info_text = info_text .. '东经'
            else
                info_text = info_text .. '西经'
            end
            info_text = info_text .. string.format('%.6f', longitude * 1.0 / 1000000)
            location_data:append_text(info_text)
        else
            location_data:add_expert_info(PI_PROTOCOL, PI_WARN, 'GPS data invalid')
        end

        return total_bytes
    end

    local dissect_realtime_data_extreme = function(buf, pinfo, tree, offset, len)
        local total_bytes = 15
        local extreme_data = tree:add(buf(offset, total_bytes), 'Extreme Data(极值数据)')

        local item = extreme_data:add(f.extreme_data_max_voltage_subsystem_code, buf(offset + 1, 1))
        item:append_text(', ' .. format_value_as_text(buf(offset + 1, 1):uint(), 1, 0, 1, '', item))

        item = extreme_data:add(f.extreme_data_max_voltage_single_code, buf(offset + 2, 1))
        item:append_text(', ' .. format_value_as_text(buf(offset + 2, 1):uint(), 1, 0, 1, '', item))

        item = extreme_data:add(f.extreme_data_max_voltage, buf(offset + 3, 2))
        item:append_text(', ' .. format_value_as_text(buf(offset + 3, 2):uint(), 2, 0, 1000, 'V', item))

        item = extreme_data:add(f.extreme_data_min_voltage_subsystem_code, buf(offset + 5, 1))
        item:append_text(', ' .. format_value_as_text(buf(offset + 5, 1):uint(), 1, 0, 1, '', item))

        item = extreme_data:add(f.extreme_data_min_voltage_single_code, buf(offset + 6, 1))
        item:append_text(', ' .. format_value_as_text(buf(offset + 6, 1):uint(), 1, 0, 1, '', item))

        item = extreme_data:add(f.extreme_data_min_voltage, buf(offset + 7, 2))
        item:append_text(', ' .. format_value_as_text(buf(offset + 7, 2):uint(), 2, 0, 1000, 'V', item))

        item = extreme_data:add(f.extreme_data_max_temperature_subsystem_code, buf(offset + 9, 1))
        item:append_text(', ' .. format_value_as_text(buf(offset + 9, 1):uint(), 1, 0, 1, '', item))

        item = extreme_data:add(f.extreme_data_max_temperature_probe_code, buf(offset + 10, 1))
        item:append_text(', ' .. format_value_as_text(buf(offset + 10, 1):uint(), 1, 0, 1, '', item))

        item = extreme_data:add(f.extreme_data_max_temperature, buf(offset + 11, 1))
        item:append_text(', ' .. format_value_as_text(buf(offset + 11, 1):uint(), 1, -40, 1, '℃', item))

        item = extreme_data:add(f.extreme_data_min_temperature_subsystem_code, buf(offset + 12, 1))
        item:append_text(', ' .. format_value_as_text(buf(offset + 12, 1):uint(), 1, 0, 1, '', item))

        item = extreme_data:add(f.extreme_data_min_temperature_probe_code, buf(offset + 13, 1))
        item:append_text(', ' .. format_value_as_text(buf(offset + 13, 1):uint(), 1, 0, 1, '', item))

        item = extreme_data:add(f.extreme_data_min_temperature, buf(offset + 14, 1))
        item:append_text(', ' .. format_value_as_text(buf(offset + 14, 1):uint(), 1, -40, 1, '℃', item))

        return total_bytes
    end

    local dissect_realtime_data_alarm = function(buf, pinfo, tree, offset, len)
        local total_alarm = 0
        local alarm_data = tree:add(buf(offset, 2), 'Alarm Data(报警数据)')
        alarm_data:add(f.alarm_data_higest_level, buf(offset + 1, 1))

        offset = offset + 2
        local alarm_flag = alarm_data:add(f.alarm_flag, buf(offset, 4))
        if buf(offset, 4):uint() == 0 then
            alarm_flag:append_text(', No Alarm')
        else
            alarm_flag:add(f.alarm_flag_temperture, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_battery_high_temperature, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_energy_voltage_over, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_energy_voltage_low, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_energy_soc_low, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_battery_single_voltage_over, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_battery_single_voltage_low, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_soc_high, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_soc_jump, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_chargeable_not_match, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_battery_single_consistency, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_insulation, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_dcdc_temperature, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_brake_system, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_dcdc_status, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_motor_controller_temperature, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_high_voltage_interlock_status, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_motor_temperature, buf(offset, 4))
            alarm_flag:add(f.alarm_flag_energy_type_overcharge, buf(offset, 4))
        end

        offset = offset + 4

        local charge_alarm_count = buf(offset, 1):uint()
        total_alarm = total_alarm + charge_alarm_count
        local alarm_chargeable = alarm_data:add(buf(offset, 1 + charge_alarm_count * 4),
            'Chargeable Alarm, Count=' .. charge_alarm_count)
        local item = alarm_chargeable:add(f.alarm_chargable_alarm_count, buf(offset, 1))
        offset = offset + 1
        for i = 0, charge_alarm_count - 1 do
            item = alarm_chargeable:add(f.alarm_chargeable_alarm_code, buf(offset, 4))
            offset = offset + 4
        end

        local motor_alarm_count = buf(offset, 1):uint()
        total_alarm = total_alarm + motor_alarm_count
        local alarm_motor = alarm_data:add(buf(offset, 1 + motor_alarm_count * 4),
            'Motor Alarm, Count=' .. motor_alarm_count)
        item = alarm_motor:add(f.alarm_motor_alarm_count, buf(offset, 1))
        offset = offset + 1
        for i = 0, motor_alarm_count - 1 do
            item = alarm_motor:add(f.alarm_motor_alarm_code, buf(offset, 4))
            offset = offset + 4
        end

        local engine_alarm_count = buf(offset, 1):uint()
        total_alarm = total_alarm + engine_alarm_count
        local alarm_engine = alarm_data:add(buf(offset, 1 + engine_alarm_count * 4),
            'Engine Alarm, Count=' .. engine_alarm_count)
        item = alarm_engine:add(f.alarm_engine_alarm_count, buf(offset, 1))
        offset = offset + 1
        for i = 0, engine_alarm_count - 1 do
            item = alarm_engine:add(f.alarm_engine_alarm_code, buf(offset, 4))
            offset = offset + 4
        end

        local other_alarm_count = buf(offset, 1):uint()
        total_alarm = total_alarm + other_alarm_count
        local alarm_other = alarm_data:add(buf(offset, 1 + other_alarm_count * 4),
            'Other Alarm, Count=' .. other_alarm_count)
        item = alarm_other:add(f.alarm_other_alarm_count, buf(offset, 1))
        offset = offset + 1
        for i = 0, other_alarm_count - 1 do
            item = alarm_other:add(f.alarm_other_alarm_code, buf(offset, 4))
            offset = offset + 4
        end

        local total_bytes = total_alarm * 4 + 10
        alarm_data:set_len(total_bytes)
        alarm_data:append_text(', Total Count=' .. total_alarm)

        return total_bytes
    end

    local dissect_realtime_data_battery_voltage = function(buf, pinfo, tree, offset, len)
        local pack_count = buf(offset + 1, 1):uint()
        local pack_root = tree:add(buf(offset, 2),
            'Battery Pack Voltage(可充电储能装置电压数据), Count=' .. pack_count)
        pack_root:add(f.battery_voltage_pack_count, buf(offset + 1, 1))
        local total_bytes = 2
        offset = offset + 2
        for i = 0, pack_count - 1 do
            local cell_count = buf(offset + 9, 1):uint()
            local pack_index = buf(offset, 1):uint()
            local this_size = 10 + cell_count * 2
            local pack_data = pack_root:add(buf(offset, this_size), 'Battery Pack Voltage, index=' .. pack_index)
            local item = pack_data:add(f.battery_voltage_pack_index, buf(offset, 1))
            item = pack_data:add(f.battery_voltage_pack_voltage, buf(offset + 1, 2))
            item:append_text(', ' .. format_value_as_text(buf(offset + 1, 2):uint(), 2, 0, 10, 'V', item))
            item = pack_data:add(f.battery_voltage_pack_current, buf(offset + 3, 2))
            item:append_text(', ' .. format_value_as_text(buf(offset + 3, 2):uint(), 2, -10000, 10, 'A', item))
            item = pack_data:add(f.battery_voltage_single_total_count, buf(offset + 5, 2))
            item = pack_data:add(f.battery_voltage_single_index, buf(offset + 7, 2))
            item = pack_data:add(f.battery_voltage_single_count, buf(offset + 9, 1))
            local cell_data = pack_data:add(buf(offset + 10, cell_count * 2), 'Single Voltages: ')
            local voltage_text = ''
            for j = 0, cell_count - 1 do
                local cell_item = cell_data:add(f.battery_voltage_single_voltage, buf(offset + 10 + j * 2, 2))
                local voltage = buf(offset + 10 + j * 2, 2):uint()
                local item_text = format_value_as_text(voltage, 2, 0, 10, 'V', cell_item)
                voltage_text = voltage_text .. item_text
                if j < cell_count - 1 then
                    voltage_text = voltage_text .. ', '
                end
                cell_item:append_text(', ' .. item_text .. ', index=' .. j + 1)
            end
            cell_data:append_text(voltage_text)
            total_bytes = total_bytes + this_size
            offset = offset + this_size
        end
        return total_bytes
    end

    local dissect_realtime_data_battery_temperature = function(buf, pinfo, tree, offset, len)
        local pack_count = buf(offset + 1, 1):uint()
        local pack_root = tree:add(buf(offset, 2),
            'Battery Pack Temperature(可充电储能装置温度数据), Count=' .. pack_count)
        pack_root:add(f.battery_temperature_pack_count, buf(offset + 1, 1))
        local total_bytes = 2
        offset = offset + 2
        for i = 0, pack_count - 1 do
            local pack_index = buf(offset, 1):uint()
            local probe_count = buf(offset + 1, 2):uint()
            total_bytes = total_bytes + 3 + probe_count
            local pack_data = pack_root:add(buf(offset, 3 + probe_count),
                'Battery Pack Temperature, index=' .. pack_index)
            pack_data:add(f.battery_temperature_pack_index, buf(offset, 1))
            pack_data:add(f.battery_temperature_probe_count, buf(offset + 1, 2))
            local probe_data = pack_data:add(buf(offset + 3, probe_count), 'Probe Temperatures: ')
            local temperature_text = ''
            for j = 0, probe_count - 1 do
                local probe_item = probe_data:add(f.battery_temperature_probe, buf(offset + 3 + j, 1))
                local temperature = buf(offset + 3 + j, 1):uint()
                local item_text = format_value_as_text(temperature, 1, -40, 1, '℃', probe_item)
                temperature_text = temperature_text .. item_text
                if j < probe_count - 1 then
                    temperature_text = temperature_text .. ', '
                end
                probe_item:append_text(', ' .. item_text .. ', index=' .. j + 1)
            end
            probe_data:append_text(temperature_text)
            offset = offset + probe_count + 3
        end
        pack_root:set_len(total_bytes)
        return total_bytes
    end

    local dissect_realtime_data_customize = function(buf, pinfo, tree, offset, len)
        local data_bytes = buf(offset + 1, 2):uint()
        local total_bytes = data_bytes - 100

        local custimize_data = tree:add(buf(offset, total_bytes), 'Customize Data(自定义数据)')

        return total_bytes
    end

    local dissect_gb32960_single_cmd_common_data = function(buf, pinfo, tree, offset, len, title)
        offset = offset + 24
        local realtime_data = tree:add(buf(offset, len), title)
        if len >= 6 then
            dissect_item_datetime(buf, pinfo, tree, realtime_data, offset, len)
            offset = offset + 6
            len = len - 6
        else
            realtime_data:add_expert_info(PI_MALFORMED, PI_ERROR, 'Invalid datetime length')
            return
        end

        while len > 0 do
            local next_type = buf(offset, 1):uint()
            if next_type == 0x01 then
                -- 0x01: 整车状态, 20 bytes
                local proceed = dissect_realtime_data_vehicle_status(buf, pinfo, realtime_data, offset, len)
                offset = offset + proceed
                len = len - proceed
            elseif next_type == 0x02 then
                -- 0x02: 驱动电机数据
                local proceed = dissect_realtime_data_motor(buf, pinfo, realtime_data, offset, len)
                offset = offset + proceed
                len = len - proceed
            elseif next_type == 0x03 then
                -- 0x03: 燃料电池数据
                local proceed = dissect_realtime_data_fuel_cell(buf, pinfo, realtime_data, offset, len)
                offset = offset + proceed
                len = len - proceed
            elseif next_type == 0x04 then
                -- 0x04: 发动机数据
                local proceed = dissect_realtime_data_engine(buf, pinfo, realtime_data, offset, len)
                offset = offset + proceed
                len = len - proceed
            elseif next_type == 0x05 then
                -- 0x05: 车辆位置数据
                local proceed = dissect_realtime_data_location(buf, pinfo, realtime_data, offset, len)
                offset = offset + proceed
                len = len - proceed
            elseif next_type == 0x06 then
                -- 0x06: 极值数据
                local proceed = dissect_realtime_data_extreme(buf, pinfo, realtime_data, offset, len)
                offset = offset + proceed
                len = len - proceed
            elseif next_type == 0x07 then
                -- 0x07: 报警数据
                local proceed = dissect_realtime_data_alarm(buf, pinfo, realtime_data, offset, len)
                offset = offset + proceed
                len = len - proceed
            elseif next_type == 0x08 then
                -- 0x08: 可充电储能装置电压数据
                local proceed = dissect_realtime_data_battery_voltage(buf, pinfo, realtime_data, offset, len)
                offset = offset + proceed
                len = len - proceed
            elseif next_type == 0x09 then
                -- 0x09: 可充电储能装置温度数据
                local proceed = dissect_realtime_data_battery_temperature(buf, pinfo, realtime_data, offset, len)
                offset = offset + proceed
                len = len - proceed
            else
                local proceed = dissect_realtime_data_customize(buf, pinfo, realtime_data, offset, len)
                offset = offset + proceed
                len = len - proceed
            end
        end
    end

    local dissect_gb32960_single_cmd_reissue_data = function(buf, pinfo, tree, offset, len)
        return dissect_gb32960_single_cmd_common_data(buf, pinfo, tree, offset, len, 'Reissue Data(补发数据)')
    end

    local dissect_gb32960_single_cmd_realtime_data = function(buf, pinfo, tree, offset, len)
        return dissect_gb32960_single_cmd_common_data(buf, pinfo, tree, offset, len, 'Realtime Data(实时数据)')
    end

    local dissect_gb32960_single_cmd = function(buf, pinfo, tree, offset, len)
        local info_text = ''
        local cmd = buf(offset + 2, 1):uint()
        local cmd_item = tree:add(f.cmd, buf(offset + 2, 1))
        local cmd_text = cmd_type_valstr[cmd] or 'Unknown'
        tree:append_text(', ' .. cmd_text)
        local vin = dissect_item_vin(buf, pinfo, tree, offset + 4, len)
        local enc = dissect_item_encryption(buf, pinfo, tree, offset + 21, len)
        dissect_item_datalen(buf, pinfo, tree, offset + 22, len)
        if cmd == 1 then
            dissect_gb32960_single_cmd_vehicle_login(buf, pinfo, tree, offset, len)
            info_text = 'Vehicle Login: ' .. vin
        elseif cmd == 2 then
            dissect_gb32960_single_cmd_realtime_data(buf, pinfo, tree, offset, len)
            info_text = 'Realtime Data: ' .. vin
        elseif cmd == 3 then
            dissect_gb32960_single_cmd_reissue_data(buf, pinfo, tree, offset, len)
            info_text = 'Reissue Data: ' .. vin
        elseif cmd == 4 then
            info_text = 'Vehicle Logout: ' .. vin
        elseif cmd == 5 then
            info_text = 'Platform Login: ' .. vin
        elseif cmd == 6 then
            info_text = 'Platform Logout: ' .. vin
        elseif cmd == 7 then
            info_text = 'Heartbeat: ' .. vin
        elseif cmd == 8 then
            info_text = 'Terminal Time Sync: ' .. vin
        else
            info_text = 'Command ' .. cmd .. ': ' .. vin
        end
        return info_text
    end

    local dissect_gb32960_single = function(buf, pinfo, root, offset, len)
        local info_text = ''
        local tree = root:add(proto, buf(offset, len + 25))
        local cmd = buf(offset + 2, 1):uint()
        if (cmd > 0 and cmd < 4 and len <= 6) or cmd == 0xfe then
            -- response
            info_text = dissect_gb32960_single_resp(buf, pinfo, tree, offset, len)
        else
            -- command
            info_text = dissect_gb32960_single_cmd(buf, pinfo, tree, offset, len)
        end
        return info_text
    end

    local dissect_gb32960 = function(buf, pinfo, root, offset)
        local pktlen = buf:len()
        local info_text = ''
        local next_offset = offset
        while next_offset < pktlen - 1 do
            -- start from '##'
            local magic0 = buf(next_offset, 1):uint()
            local magic1 = buf(next_offset + 1, 1):uint()
            if magic0 == 0x23 and magic1 == 0x23 then
                local remain_bytes = pktlen - next_offset
                if remain_bytes < 24 then
                    -- we need more bytes
                    return remain_bytes - 24, info_text
                end
                local data_length = buf:range(next_offset + 22, 2):uint()
                local total_length = 24 + data_length + 1
                if remain_bytes < total_length then
                    -- we need more bytes
                    return total_length - remain_bytes, info_text
                end
                info_text = dissect_gb32960_single(buf, pinfo, root, next_offset, data_length)
                return next_offset - offset + total_length, info_text
            elseif magic1 == 0x23 then
                next_offset = next_offset + 1
            else
                next_offset = next_offset + 2
            end
        end
        return next_offset - offset, info_text
    end

    function proto.dissector(buf, pinfo, tree)
        pinfo.cols.protocol = 'GB32960'

        local info_text = ''
        local info_count = 0
        local pktlen = buf:len()
        local bytes_consumed = 0

        local format_pinfo = function(pinfo, text, count)
            if text ~= '' then
                if count > 3 then
                    pinfo.cols.info = 'GB32960 (' .. count .. ' Packets)' .. text .. ', ...'
                else
                    pinfo.cols.info = 'GB32960' .. text
                end
            end
        end

        while bytes_consumed < pktlen do
            local result, text = dissect_gb32960(buf, pinfo, tree, bytes_consumed)
            if result > 0 then
                bytes_consumed = bytes_consumed + result
                info_count = info_count + 1
                if (info_count <= 3) then
                    info_text = info_text .. ', ' .. text
                end
            elseif result == 0 then
                format_pinfo(pinfo, info_text, info_count)
                return 0
            else
                -- we need more bytes
                pinfo.desegment_offset = bytes_consumed

                -- invert the negative result so it's a positive number
                result = -result

                pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                format_pinfo(pinfo, info_text, info_count)
                return pktlen
            end
        end

        format_pinfo(pinfo, info_text, info_count)
        return bytes_consumed
    end

    local dissectors = DissectorTable.get('tcp.port')
    dissectors:add(default_settings.port, proto)

end
