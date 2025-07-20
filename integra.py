#!/usr/bin/env python3

import datetime
import socket


def raw_name_to_string(raw_data, start=3, end=16):
    return "".join(["%s" % chr(el) for el in raw_data[start : start + end]]).rstrip(" ")


def get_set_bits(byte_array, is_hex=True):
    """Loop over an array with 8-byte numbers and return the bits which are set
    on them.
    If numbers are in HEX, set the is_hex parameter.

    e.g. byte_array = [06, 20, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
                           00, 00, 00, 80]

         result -> [2, 3, 14, 128]
    """
    ret = []
    c = 0

    for i in byte_array:
        if is_hex:
            # convert hex to int
            i = int(str(i), 16)

        # loop over bit positions
        for bit_pos in range(7, -1, -1):
            # check if current bit is set
            if i & (128 >> bit_pos):
                ret.append(c + 8 - bit_pos)

        c += 8

    return ret


def bit_to_int(bit_string):
    """convert bit-string to int"""
    return int(bit_string, 2)


def int_to_bit(value):
    """convert int to bit-string"""
    return "{0:08b}".format(value)


event_class_def = {
    "000": "zone and tamper alarms",
    "001": "partition and expander alarms",
    "010": "arming, disarming, alarm clearing",
    "011": "zone bypasses and unbypasses",
    "100": "access control",
    "101": "troubles",
    "110": "user functions",
    "111": "system events",
}


class Device:
    def __init__(self, id_, name, type_):
        self.id_ = id_
        self.name = name
        self.type_ = type_

    def __str__(self):
        return "ID: {0}, Name: {1}, Type: {2}".format(self.id_, self.name, self.type_)


class Partition(Device):
    pass


class Objects(Device):
    def __init__(self, partition, id_, name, type_):
        super(Objects, self).__init__(id_, name, type_)
        self.partition = partition

    def __str__(self):
        return "ID: {0}, Partition: {1}, Name: {2}, Type: {3}".format(
            self.id_, self.partition, self.name, self.type_
        )


class Output(Device):
    pass


class Communication:
    def __init__(self):
        self.host = ""
        self.port = 0
        self.usercode = None
        self._connection = None

    # command: bytearray
    def checksum(self, command):
        crc = 0x147A
        for b in command:
            bit = (crc & 0x8000) >> 15
            crc = ((crc << 1) & 0xFFFF) | bit
            crc = crc ^ 0xFFFF
            crc = crc + (crc >> 8) + b

        return (((crc >> 8) & 0xFF), (crc & 0xFF))

    @property
    def connection(self):
        if self._connection is None:
            self._connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._connection.connect((self.host, self.port))

        return self._connection

    def openConnection(self):
        return self.connection

    def closeConnection(self):
        if self.connection is not None:
            self.connection.close()

    # command: array
    def sendCommand(self, command, debug=False):
        buffer_ = b""
        attempt = 0
        readBytes = 0
        debug_cmd = []
        byte_fefe = bytearray([0xFE, 0xFE])
        byte_fe0d = bytearray([0xFE, 0x0D])

        while True:
            debug_cmd = []
            attempt += 1
            send = bytearray()

            self.connection.sendall(byte_fefe)
            send.extend(byte_fefe)

            for b in command:
                send.append(b)
                if b == 0xFE:
                    send.append(0xF0)

            debug_cmd.extend(byte_fefe)
            debug_cmd.extend(byte_fe0d)
            debug_cmd.extend(send)

            # send = bytearray()

            for b in self.checksum(command):
                send.append(b)
                if b == 0xFE:
                    send.append(0xF0)

            debug_cmd.extend(send)

            send.extend(byte_fe0d)
            self.connection.sendall(send)

            buffer_ = self.connection.recv(128)
            readBytes = len(buffer_)

            if (buffer_[0] != buffer_[1] or buffer_[0] != 0xFE) and attempt < 3:
                pass
            else:
                break

        if debug:
            print("command:\t")
            for i in debug_cmd:
                print(str(hex(i))[2:].upper())
            print()

        response = []
        for i in range(3, readBytes - 4):
            response.append(buffer_[i])
            if buffer_[i] == 0xFE and buffer_[i + 1] == 0xF0:
                i += 1

        if debug:
            print("response:\t", response)

        return response

    def sendAuthenticatedCommand(self, command, arguments=None, debug=False):
        parameters = []
        parameters.extend(command)
        parameters.extend(self.usercode)

        if arguments is not None:
            parameters.extend(arguments)

        parameters = tuple(parameters)

        return self.sendCommand(parameters, debug=debug)


user_type = {
    0: "Normal",
    1: "Single",
    2: "TimeRenewable",
    3: "TimeNotRenewable",
    4: "Duress",
    5: "MonoOutputs",
    6: "BiOutputs",
    7: "ParitionTemporaryBlocking",
    8: "AccessToCashMachine",
    9: "Guard",
    10: "Schedule",
}


class User:
    def __init__(self, raw_data):
        self._id = raw_data[0]
        self._partitions = raw_data[1:5]
        self._type = raw_data[5]
        self.time = raw_data[6]
        self.timetmp = raw_data[7]
        self.permissions = UserPermissions(raw_data[8:11])
        self.name = raw_name_to_string(raw_data, 11, 26)
        self.ext_attr = raw_data[27]

        # user_type_bit = '{0:08b}'.format(x[5])

    @property
    def change_code(self):
        "returns true if the user needs to change his code"
        return bool((self._type & 0x80))

    @property
    def reused_code(self):
        "returns true if this users code was tried to be reused"
        return bool(self._type & 0x40)

    @property
    def user_type(self):
        return user_type[self.get_type()]

    def get_type(self):
        return self._type & 0x0F

    def set_type(self, value):
        self._type = value & 0x0F

    @property
    def partitions(self):
        return get_set_bits(self._partitions, is_hex=False)

    def __str__(self):
        ret = ""
        ret += "ID: {0}\n".format(self._id)
        ret += "Nane: {0}\n".format(self.name)
        ret += "Type: {0}\n".format(self.user_type)
        ret += "Code change required: {0}\n".format(self.change_code)
        ret += "This code was reused: {0}\n".format(self.reused_code)
        ret += "Time: {0}\n".format(self.time)
        ret += "Time tmp: {0}\n".format(self.timetmp)
        ret += "Partitions: {0}\n".format(self.partitions)
        ret += "Extended attributes: {0}\n".format(self.ext_attr)

        ret += "Permissions:\n"
        for l in self.permissions.matrix().split("\n"):
            ret += "\t{0}\n".format(l)

        return ret


class UserPermissions:
    all_permissions = [
        "Arming",
        "Disarming",
        "AlarmClearingOwnPartition",
        "AlarmClearingOwnObject",
        "AlarmClearing",
        "ArmDefering",
        "CodeChanging",
        "UsersEditing",
        "ZonesBypassing",
        "ClockSettings",
        "TroublesViewing",
        "EventsViewing",
        "ZonesResetting",
        "OptionsChanging",
        "Tests",
        "Downloading",
        "CanAlwaysDisarm",
        "VoiceMessageClearing",
        "GuardX",
        "AccessToTemporaryBlockedPartitions",
        "Entering1stCode",
        "Entering2ndCode",
        "OutputsControl",
        "ClearingLatchedOutputs",
    ]

    def __init__(self, permissions):
        self._permissions = permissions

    def matrix(self):
        ret = ""

        for p in self.all_permissions:
            ret += "{0}:\t\t{1}\n".format(p, getattr(self, p.lower()))

        return ret

    @property
    def arming(self):
        return bool(self._permissions[0] & 0x01)

    @arming.setter
    def arming(self, value):
        if value:
            self._permissions[0] |= 0x01

    @property
    def disarming(self):
        return bool(self._permissions[0] & 0x02)

    @disarming.setter
    def disarming(self, value):
        if value:
            self._permissions[0] |= 0x02

    @property
    def alarmclearingownpartition(self):
        return bool(self._permissions[0] & 0x04)

    @alarmclearingownpartition.setter
    def alarmclearingownpartition(self, value):
        if value:
            self._permissions[0] |= 0x04

    @property
    def alarmclearingownobject(self):
        return bool(self._permissions[0] & 0x08)

    @alarmclearingownobject.setter
    def alarmclearingownobject(self, value):
        if value:
            self._permissions[0] |= 0x08

    @property
    def alarmclearing(self):
        return bool(self._permissions[0] & 0x10)

    @alarmclearing.setter
    def alarmclearing(self, value):
        if value:
            self._permissions[0] |= 0x10

    @property
    def armdefering(self):
        return bool(self._permissions[0] & 0x20)

    @armdefering.setter
    def armdefering(self, value):
        if value:
            self._permissions[0] |= 0x20

    @property
    def codechanging(self):
        return bool(self._permissions[0] & 0x40)

    @codechanging.setter
    def codechanging(self, value):
        if value:
            self._permissions[0] |= 0x40

    @property
    def usersediting(self):
        return bool(self._permissions[0] & 0x80)

    @usersediting.setter
    def usersediting(self, value):
        if value:
            self._permissions[0] |= 0x80

    @property
    def zonesbypassing(self):
        return bool(self._permissions[1] & 0x01)

    @zonesbypassing.setter
    def zonesbypassing(self, value):
        if value:
            self._permissions[1] |= 0x01

    @property
    def clocksettings(self):
        return bool(self._permissions[1] & 0x02)

    @clocksettings.setter
    def clocksettings(self, value):
        if value:
            self._permissions[1] |= 0x02

    @property
    def troublesviewing(self):
        return bool(self._permissions[1] & 0x04)

    @troublesviewing.setter
    def troublesviewing(self, value):
        if value:
            self._permissions[1] |= 0x04

    @property
    def eventsviewing(self):
        return bool(self._permissions[1] & 0x08)

    @eventsviewing.setter
    def eventsviewing(self, value):
        if value:
            self._permissions[1] |= 0x08

    @property
    def zonesresetting(self):
        return bool(self._permissions[1] & 0x10)

    @zonesresetting.setter
    def zonesresetting(self, value):
        if value:
            self._permissions[1] |= 0x10

    @property
    def optionschanging(self):
        return bool(self._permissions[1] & 0x20)

    @optionschanging.setter
    def optionschanging(self, value):
        if value:
            self._permissions[1] |= 0x20

    @property
    def tests(self):
        return bool(self._permissions[1] & 0x40)

    @tests.setter
    def tests(self, value):
        if value:
            self._permissions[1] |= 0x40

    @property
    def downloading(self):
        return bool(self._permissions[1] & 0x80)

    @downloading.setter
    def downloading(self, value):
        if value:
            self._permissions[1] |= 0x80

    @property
    def arming(self):
        return bool(self._permissions[2] & 0x01)

    @arming.setter
    def canalwaysdisarm(self, value):
        if value:
            self._permissions[2] |= 0x01

    @property
    def canalwaysdisarm(self):
        return bool(self._permissions[2] & 0x01)

    @arming.setter
    def arming(self, value):
        if value:
            self._permissions[2] |= 0x01

    @property
    def voicemessageclearing(self):
        return bool(self._permissions[2] & 0x02)

    @voicemessageclearing.setter
    def voicemessageclearing(self, value):
        if value:
            self._permissions[2] |= 0x02

    @property
    def guardx(self):
        return bool(self._permissions[2] & 0x04)

    @guardx.setter
    def guardx(self, value):
        if value:
            self._permissions[2] |= 0x04

    @property
    def accesstotemporaryblockedpartitions(self):
        return bool(self._permissions[2] & 0x08)

    @accesstotemporaryblockedpartitions.setter
    def accesstotemporaryblockedpartitions(self, value):
        if value:
            self._permissions[2] |= 0x08

    @property
    def entering1stcode(self):
        return bool(self._permissions[2] & 0x10)

    @entering1stcode.setter
    def entering1stcode(self, value):
        if value:
            self._permissions[2] |= 0x10

    @property
    def entering2ndcode(self):
        return bool(self._permissions[2] & 0x20)

    @entering2ndcode.setter
    def entering2ndcode(self, value):
        if value:
            self._permissions[2] |= 0x20

    @property
    def outputscontrol(self):
        return bool(self._permissions[2] & 0x40)

    @outputscontrol.setter
    def outputscontrol(self, value):
        if value:
            self._permissions[2] |= 0x40

    @property
    def clearinglatchedoutputs(self):
        return bool(self._permissions[2] & 0x80)

    @clearinglatchedoutputs.setter
    def clearinglatchedoutputs(self, value):
        if value:
            self._permissions[2] |= 0x80


class Integra:
    def __init__(self, host, port, usercode, debug=False):
        self.connection = Communication()
        self.connection.host = host
        self.connection.port = port
        self.connection.usercode = self.convertUserCode(usercode)

        self.partition = {}
        self.zone = {}
        self.output = {}
        self.users = {}

        self.debug = debug

    def hardwareModel(self, code):
        if code == 0:
            return "24"
        elif code == 1:
            return "32"
        elif code == 2:
            return "64"
        elif code == 3:
            return "128"
        elif code == 4:
            return "128-WRL SIM300"
        elif code == 132:
            return "128-WRL LEON"
        elif code == 66:
            return "64 PLUS"
        elif code == 67:
            return "128 PLUS"

        return "UNKNOWN"

    # converts UserCode specified as string (1234) to format used by Integra (0x12 0x34)
    def convertUserCode(self, usercode, prefix=""):
        result = bytearray()
        code = prefix + usercode

        for i in range(0, len(usercode), 2):
            s = usercode[i : i + 2]

            if len(s) == 2:
                s = "0x{0}".format(s)
            else:
                s = "0x{0}F".format(s)

            print(int(s, 16))
            result.append(int(s, 16))

        # Integra expects either 4 bytes or 8 if prefix used.
        if prefix == "" and len(result) < 4:
            for i in range(len(result), 4):
                result.append(0xFF)
        elif not prefix == "" and len(result) < 8:
            for i in range(len(result), 8):
                result.append(0xFF)

        return result

    def getVersion(self):
        resp = self.connection.sendCommand([0x7E], debug=self.debug)

        result = "INTEGRA {0}".format(self.hardwareModel(resp[0]))
        result += (
            " "
            + chr(resp[1])
            + "."
            + chr(resp[2])
            + chr(resp[3])
            + " "
            + chr(resp[4])
            + chr(resp[5])
            + chr(resp[6])
            + chr(resp[7])
        )
        result += (
            "-" + chr(resp[8]) + chr(resp[9]) + "-" + chr(resp[10]) + chr(resp[11])
        )
        result += " LANG: " + ("English" if resp[12] == 1 else "Other")
        result += (
            " SETTINGS: "
            + ("stored" if resp[13] == 0xFF else "NOT STORED")
            + " in flash"
        )

        return result

    def __read_device_name(self, device_type, min_id, max_id):
        for i in range(min_id, max_id + 1):
            resp = self.connection.sendCommand([0xEE, device_type, i], debug=self.debug)

            if not len(resp) > 4:
                continue

            name = raw_name_to_string(resp)

            yield (i, name, resp)

    def _read_device_name(self, device_type, index):
        resp = self.connection.sendCommand([0xEE, device_type, index], debug=self.debug)

        if not len(resp) > 4:
            raise KeyError("key does not exist")

        name = raw_name_to_string(resp)

        return (i, name, resp)

    def read_partitions(self):
        for i, name, resp in self.__read_device_name(0x0, 1, 32):
            if not resp[3] == 0xFE:
                self.partition[i] = Partition(i, name, resp[2])

        return self.partition

    def read_expander(self):
        for i, name, resp in self.__read_device_name(0x3, 129, 192):
            if not resp[3] == 0xFE:
                self.zone[i] = Objects(resp[18], i, name, resp[2])

        return self.zone

    def read_zone(self, index):
        i, name, resp = self._read_device_name(0x5, index)
        return Objects(resp[19], i, name, resp[2])

    def read_zones(self):
        for i, name, resp in self.__read_device_name(0x5, 1, 128):
            if not resp[3] == 0xFE:
                self.zone[i] = Objects(resp[19], i, name, resp[2])

        return self.zone

    def read_outputs(self):
        for i, name, resp in self.__read_device_name(0x4, 1, 128):
            if not resp[2] == 0:
                self.output[i] = Output(i, name, resp[2])

        return self.output

    def read_users(self):
        for i in range(1, 2):
            resp = self.connection.sendAuthenticatedCommand(
                [0xE1], [i], debug=self.debug
            )

            if not len(resp) == 1 and not resp[0] == 0x03:
                # users.Add(i, new User(i, resp.Skip(1).Take(4).ToArray(), resp[5], resp[6], resp[7], resp.Skip(8).Take(3).ToArray(), Encoding.UTF8.GetString(resp, 11, 16)))

                self.users[i] = User(resp)

        return self.users

    def read_event(self, counter=15):
        command = [0x8C, 0xFF, 0xFF, 0xFF]

        c = 1
        while counter > 0:
            resp = self.connection.sendCommand(command, debug=self.debug)

            print(c)
            c += 1
            next_event_index = self.parse_event(resp)
            command = [0x8C]
            command.extend(next_event_index)

            counter -= 1

    def parse_event(self, raw_data):
        event = raw_data[0:8]
        event_index = raw_data[8:11]
        old_event_index = raw_data[11:14]

        print(event)
        print(event[1])
        print(event[2])

        print()
        day = bit_to_int(int_to_bit(event[1])[3:])
        month = bit_to_int(int_to_bit(event[2])[0:4])

        year = bit_to_int(int_to_bit(event[0])[0:2])
        current_year = datetime.datetime.now().year
        current_year_mod = current_year % 4
        for i in range(current_year, current_year - 5, -1):
            if i % 4 == current_year_mod:
                year = i
                break

        minutes = bit_to_int(int_to_bit(event[2])[4:] + int_to_bit(event[3]))
        hours = minutes / 60
        time = "{0}:{1}".format(hours, minutes - hours * 60)

        print("Date: {0}/{1}/{2} {3}".format(year, month, day, time))

        event_class = int_to_bit(event[1])[0:3]
        print(event_class_def[event_class])

        return event_index

    @property
    def zones_violations(self):
        return get_set_bits(
            self.connection.sendCommand([0x00], debug=self.debug), is_hex=False
        )

    @property
    def zones_alarm(self):
        return get_set_bits(self.connection.sendCommand([0x02], debug=self.debug))

    @property
    def armed_partitions(self):
        """really"""
        return get_set_bits(self.connection.sendCommand([0x0A], debug=self.debug))

    @property
    def partitions_alarm(self):
        return get_set_bits(self.connection.sendCommand([0x13], debug=self.debug))

    @property
    def partitions_fire_alarm(self):
        return get_set_bits(self.connection.sendCommand([0x14], debug=self.debug))

    @property
    def outputs_state(self):
        return get_set_bits(
            self.connection.sendCommand([0x17], debug=self.debug), is_hex=False
        )

    @property
    def partitions_with_violates_zones(self):
        return get_set_bits(
            self.connection.sendCommand([0x25], debug=self.debug), is_hex=False
        )

    def new_state(self):
        # print get_set_bits(self.connection.sendCommand([0x07], debug=self.debug))
        print(
            get_set_bits(
                self.connection.sendCommand([0x7F], debug=self.debug), is_hex=False
            )
        )

        print()
        for x in self.connection.sendCommand([0x7F], debug=self.debug):
            print(x)
            print(hex(x))

            print(int_to_bit(x), x)
        print()

