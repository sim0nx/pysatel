import asyncio
import collections.abc
import datetime
import logging
import typing

from async_timeout import timeout

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def raw_name_to_string(raw_data, start=3, end=16):
  return ''.join(['%s' % chr(el) for el in raw_data[start : start + end]]).rstrip(' ')


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


def set_bits(int_list: list[int], length: int):
  ret_val = 0
  for position in int_list:
    if position > length * 8:
      raise IndexError
    ret_val = ret_val | (1 << (position - 1))

  return ret_val.to_bytes(length, 'little')


def bit_to_int(bit_string):
  """Convert bit-string to int"""
  return int(bit_string, 2)


def int_to_bit(value):
  """Convert int to bit-string"""
  return f'{value:08b}'


class SACommand(asyncio.Event):
  def __init__(self, cmd: list[int]):
    super().__init__()
    self._cmd = cmd

  @property
  def cmd(self) -> int:
    return self._cmd


class SACommandPair:
  def __init__(self, tx: SACommand, rx: SACommand = None):
    self._tx = tx
    self._rx = rx

  @property
  def tx(self) -> SACommand:
    return self._tx

  @property
  def rx(self) -> SACommand | None:
    return self._rx


event_class_def = {
  '000': 'zone and tamper alarms',
  '001': 'partition and expander alarms',
  '010': 'arming, disarming, alarm clearing',
  '011': 'zone bypasses and unbypasses',
  '100': 'access control',
  '101': 'troubles',
  '110': 'user functions',
  '111': 'system events',
}


class Device:
  def __init__(self, id_, name, type_):
    self.id_ = id_
    self.name = name
    self.type_ = type_

  def __str__(self):
    return f'ID: {self.id_}, Name: {self.name}, Type: {self.type_}'


class Partition(Device):
  pass


class Objects(Device):
  def __init__(self, partition, id_, name, type_):
    super(Objects, self).__init__(id_, name, type_)
    self.partition = partition

  def __str__(self):
    return f'ID: {self.id_}, Partition: {self.partition}, Name: {self.name}, Type: {self.type_}'


class Output(Device):
  pass


user_type = {
  0: 'Normal',
  1: 'Single',
  2: 'TimeRenewable',
  3: 'TimeNotRenewable',
  4: 'Duress',
  5: 'MonoOutputs',
  6: 'BiOutputs',
  7: 'ParitionTemporaryBlocking',
  8: 'AccessToCashMachine',
  9: 'Guard',
  10: 'Schedule',
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
    """Returns true if the user needs to change his code"""
    return bool(self._type & 0x80)

  @property
  def reused_code(self):
    """Returns true if this users code was tried to be reused"""
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
    ret = ''
    ret += f'ID: {self._id}\n'
    ret += f'Nane: {self.name}\n'
    ret += f'Type: {self.user_type}\n'
    ret += f'Code change required: {self.change_code}\n'
    ret += f'This code was reused: {self.reused_code}\n'
    ret += f'Time: {self.time}\n'
    ret += f'Time tmp: {self.timetmp}\n'
    ret += f'Partitions: {self.partitions}\n'
    ret += f'Extended attributes: {self.ext_attr}\n'

    ret += 'Permissions:\n'
    for l in self.permissions.matrix().split('\n'):
      ret += f'\t{l}\n'

    return ret


class UserPermissions:
  all_permissions = [
    'Arming',
    'Disarming',
    'AlarmClearingOwnPartition',
    'AlarmClearingOwnObject',
    'AlarmClearing',
    'ArmDefering',
    'CodeChanging',
    'UsersEditing',
    'ZonesBypassing',
    'ClockSettings',
    'TroublesViewing',
    'EventsViewing',
    'ZonesResetting',
    'OptionsChanging',
    'Tests',
    'Downloading',
    'CanAlwaysDisarm',
    'VoiceMessageClearing',
    'GuardX',
    'AccessToTemporaryBlockedPartitions',
    'Entering1stCode',
    'Entering2ndCode',
    'OutputsControl',
    'ClearingLatchedOutputs',
  ]

  def __init__(self, permissions):
    self._permissions = permissions

  def matrix(self):
    ret = ''

    for p in self.all_permissions:
      ret += f'{p}:\t\t{getattr(self, p.lower())}\n'

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


class Integra(asyncio.Protocol):
  def __init__(self, host: str, port: int, usercode: str, debug: bool = False) -> None:
    self.host = host
    self.port = port
    self.usercode = self.convertUserCode(usercode)

    self._transport = None
    self._running = False
    self._lock = None
    self._rx_queue = None
    self._rx_task = None
    self._tx_queue = None
    self._tx_task = None

    self._raw_listeners = set()
    self._cmd_listeners = {}
    self._transformers: dict[int, collections.abc.Callable[[int, list[int]], typing.Any]] = {
      0xEE: self.transform_ee,
      0x00: self.transform_setbits,
      0x25: self.transform_setbits,
    }

    self.partition = {}
    self.zone = {}
    self.output = {}
    self.users = {}

    self.debug = debug

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
  def running(self) -> bool:
    return self._running

  async def _resume_reading(self, delay):
    await asyncio.sleep(delay)
    if self._transport:
      self._transport.resume_reading()
      logger.debug('Resume reading')

  def _delay_reading(self, delay):
    self._transport.pause_reading()
    logger.debug('Delay reading')
    asyncio.ensure_future(self._resume_reading(delay))

  def data_received(self, data: bytes):
    logger.debug('Received data')
    if self._rx_task.done():
      print(self._rx_task.exception())

    self._rx_queue.put_nowait(data)
    self._delay_reading(1)

  def connection_lost(self, exc: Exception | None):
    logger.warning('Lost connection to %s: %s', self.host, exc)
    if self._running and not self._lock.locked():
      asyncio.ensure_future(
        self._reconnect(delay=10),
      )

  async def _create_connection(self):
    loop = asyncio.get_running_loop()
    return await loop.create_connection(lambda: self, host=self.host, port=self.port)

  async def _reconnect(self, delay: int = 0):
    async with self._lock:
      await self._disconnect()
      self._flush_queue(self._rx_queue)

      await asyncio.sleep(delay)

      logger.info('Connecting to %s', self.host)
      try:
        async with timeout(5):
          self._transport, _ = await self._create_connection()
      except (TimeoutError, BrokenPipeError, ConnectionRefusedError) as exc:
        logger.warning(exc)
        asyncio.ensure_future(
          self._reconnect(delay=10),
        )
      else:
        logger.info('Connected to %s', self.host)

  async def connect(self):
    if self._running:
      logger.debug('Already connected!')
      return

    self._rx_queue = asyncio.Queue()
    self._rx_task = asyncio.ensure_future(self._rx_worker())
    self._tx_queue = asyncio.Queue()
    self._tx_task = asyncio.ensure_future(self._tx_worker())
    self._lock = asyncio.Lock()
    self._running = True
    await self._reconnect()

  async def _disconnect(self):
    if self._transport:
      logger.debug('Disconnecting from %s', self.host)
      self._transport.abort()
      self._transport = None
    self._buf = b''

  async def shutdown(self):
    async with self._lock:
      if not self._running:
        logger.debug('Already shut down!')
        return

      logger.debug('Shutting down connection to %s', self.host)
      self._running = False

      await self._disconnect()

      if self._rx_task:
        self._rx_task.cancel()
      if self._tx_task:
        self._tx_task.cancel()

      await asyncio.gather(self._tx_task, self._rx_task, return_exceptions=True)

  @staticmethod
  def _flush_queue(queue):
    while not queue.empty():
      queue.get_nowait()

    while True:
      try:
        queue.task_done()
      except ValueError:
        break

  def _write(self, msg):
    if not self._transport:
      logger.warning('Transport unavailable!')
      return False

    self._transport.write(msg)
    return True

  async def _tx_worker(self):
    while self._running:
      self._cmd = await self._tx_queue.get()
      msg = self._create_msg(self._cmd.tx.cmd)
      logger.debug('sending command: %s', self._cmd.tx.cmd)

      for tries in range(2):
        self._cmd.tx.clear()

        logger.debug('Write #%d %s', tries + 1, self._cmd.tx.cmd)

        if not self._write(msg):
          break

        try:
          async with timeout(1.5):
            await self._cmd.tx.wait()
        except TimeoutError:
          logger.warning('TX ack timeout')
          continue

        logger.debug('ACK ok')
        if self._cmd.rx is None:
          break

        # try:
        #     async with timeout(1):
        #         await self._cmd.rx.wait()
        # except TimeoutError:
        #     logger.warning('RX msg timeout')
        #     continue

        logger.debug('message ok (bufsize=%d)', len(self._buf))
        # self._write(self._ack())
        break

      logger.debug('TX task done')
      self._tx_queue.task_done()
      self._cmd = None

  async def _transaction(self, cmd: SACommandPair) -> None:
    logger.debug('Transaction %s', cmd.tx.cmd)
    await self._tx_queue.put(cmd)

  def _create_msg(self, cmd):
    send_cmd = bytearray()
    byte_fefe = bytearray([0xFE, 0xFE])
    byte_fe0d = bytearray([0xFE, 0x0D])

    send_cmd.extend(byte_fefe)

    for b in cmd:
      send_cmd.append(b)
      if b == 0xFE:
        send_cmd.append(0xF0)

    for b in self.checksum(cmd):
      send_cmd.append(b)
      if b == 0xFE:
        send_cmd.append(0xF0)

    send_cmd.extend(byte_fe0d)

    return send_cmd

  async def _process_data(self):
    readBytes = len(self._buf)
    buffer_ = self._buf

    if not (buffer_[0] == buffer_[1] and buffer_[0] == 0xFE):
      logger.debug('%d unparsable bytes.', len(self._buf))
      return False

    # command the reply was sent for
    cmd = buffer_[2]

    response = []
    for i in range(3, readBytes - 4):
      response.append(buffer_[i])
      if buffer_[i] == 0xFE and buffer_[i + 1] == 0xF0:
        i += 1

    logger.debug('%d bytes - %s', len(response), response)

    # if received command matches sent command, ack
    if self._cmd is not None and cmd == self._cmd.tx.cmd[0]:
      self._cmd.tx.set()
      self._cmd.rx.set()

    for listener in self._raw_listeners:
      await listener(response)

    if cmd in self._cmd_listeners:
      if cmd in self._transformers:
        data = self._transformers[cmd](cmd, response)
      else:
        data = response

      if len(response) >= 1:
        data_type = response[0]
      else:
        data_type = None

      if len(self._cmd_listeners[cmd]) == 1 and list(self._cmd_listeners[cmd].keys())[0] is None:
        for k in self._cmd_listeners[cmd][None]:
          await k(self, data)

      elif data_type is not None and data_type in self._cmd_listeners[cmd]:
        if data_type in self._cmd_listeners[cmd]:
          for k in self._cmd_listeners[cmd][data_type]:
            await k(self, data)

      else:
        logger.warning('Command %s did not respond.', cmd)

    return False

  async def _rx_worker(self):
    logger.debug('starting rx worker')
    while self._running:
      self._buf += await self._rx_queue.get()
      logger.debug('Receive buffer %s', self._buf)

      while self._buf and self._running:
        try:
          more = await self._process_data()
          if not more:
            break
        except Exception as e:
          logger.exception('Exception %s', e)
          break

      self._buf = b''

      self._rx_queue.task_done()

    logger.debug('rx worker done')

  # command: array
  def sendCommand(self, command, debug=False):
    buffer_ = b''
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
      print('command:\t')
      for i in debug_cmd:
        print(str(hex(i))[2:].upper())
      print()

    response = []
    for i in range(3, readBytes - 4):
      response.append(buffer_[i])
      if buffer_[i] == 0xFE and buffer_[i + 1] == 0xF0:
        i += 1

    if debug:
      print('response:\t', response)

    return response

  def sendAuthenticatedCommand(self, command, arguments=None, debug=False):
    parameters = []
    parameters.extend(command)
    parameters.extend(self.usercode)

    if arguments is not None:
      parameters.extend(arguments)

    parameters = tuple(parameters)

    return self.sendCommand(parameters, debug=debug)

  @staticmethod
  def hardwareModel(code):
    if code == 0:
      return '24'
    if code == 1:
      return '32'
    if code == 2:
      return '64'
    if code == 3:
      return '128'
    if code == 4:
      return '128-WRL SIM300'
    if code == 132:
      return '128-WRL LEON'
    if code == 66:
      return '64 PLUS'
    if code == 67:
      return '128 PLUS'

    return 'UNKNOWN'

  @staticmethod
  def convertUserCode(usercode: str, prefix: str = '') -> bytearray:
    """Converts UserCode specified as string (1234) to format used by Integra (0x12 0x34)."""
    result = bytearray()
    code = f'{prefix}{usercode}'

    for i in range(0, len(code), 2):
      s = code[i : i + 2]

      if len(s) == 2:
        s = f'0x{s}'
      else:
        s = f'0x{s}F'

      result.append(int(s, 16))

    if len(result) < 8:
      for i in range(len(result), 8):
        result.append(0xFF)

    return result

  async def getVersion(self):
    cmd = SACommandPair(SACommand([0x7E]), SACommand([0x7E]))
    await self._transaction(cmd)
    return None

    resp = self.connection.sendCommand([0x7E], debug=self.debug)

    result = f'INTEGRA {self.hardwareModel(resp[0])}'
    result += ' ' + chr(resp[1]) + '.' + chr(resp[2]) + chr(resp[3]) + ' ' + chr(resp[4]) + chr(resp[5]) + chr(resp[6]) + chr(resp[7])
    result += '-' + chr(resp[8]) + chr(resp[9]) + '-' + chr(resp[10]) + chr(resp[11])
    result += ' LANG: ' + ('English' if resp[12] == 1 else 'Other')
    result += ' SETTINGS: ' + ('stored' if resp[13] == 0xFF else 'NOT STORED') + ' in flash'

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
      raise KeyError('key does not exist')

    name = raw_name_to_string(resp)

    return (i, name, resp)

  async def read_partitions(self, monitor_partitions: list[int] | None = None):
    if monitor_partitions is None:
      for i in range(1, 32 + 1):
        if i not in self.partition:
          await self._transaction(SACommandPair(SACommand([0xEE, 0x0, i]), SACommand([0xEE, 0x0, i])))

    else:
      for i in monitor_partitions:
        if i not in self.partition:
          await self._transaction(SACommandPair(SACommand([0xEE, 0x0, i]), SACommand([0xEE, 0x0, i])))

  def transform_ee(self, cmd: int, response: list[int]):
    device_type = response[0]

    if device_type == 0x00:
      # read partitions
      if not len(response) > 4:
        return None

      name = raw_name_to_string(response)

      if not response[3] == 0xFE:
        partition = Partition(response[1], name, response[2])
        self.partition[partition.id_] = partition
        return partition

    elif device_type == 0x01:
      # read zones without partition info
      if not len(response) > 4:
        return None

      name = raw_name_to_string(response)

      if not response[3] == 0xFE:
        zone = Objects(None, response[1], name, response[2])
        self.zone[zone.id_] = zone
        return zone

    elif device_type == 0x05:
      # read zones with partition info
      if not len(response) > 4:
        return None

      name = raw_name_to_string(response)

      if not response[3] == 0xFE:
        zone = Objects(response[19], response[1], name, response[2])
        self.zone[zone.id_] = zone
        return zone

    return None

  def transform_setbits(self, cmd: int, response: list[int]):
    if cmd in (0x00, 0x25):
      is_hex = False
    else:
      is_hex = True
    res = get_set_bits(response, is_hex=is_hex)
    return res

  def read_expander(self):
    for i, name, resp in self.__read_device_name(0x3, 129, 192):
      if not resp[3] == 0xFE:
        self.zone[i] = Objects(resp[18], i, name, resp[2])

    return self.zone

  def read_zone(self, index):
    i, name, resp = self._read_device_name(0x5, index)
    return Objects(resp[19], i, name, resp[2])

  async def read_zones(self, monitor_zones: list[int] | None = None):
    """Read zones with partition info."""
    if monitor_zones is None:
      for i in range(1, 128 + 1):
        if i not in self.zone:
          # await self._transaction(SACommandPair(SACommand([0xEE, 0x5, i]), SACommand([0xEE, 0x5, i])))
          await self._transaction(SACommandPair(SACommand([0xEE, 0x1, i]), SACommand([0xEE, 0x1, i])))

    else:
      for i in monitor_zones:
        if i not in self.zone:
          await self._transaction(SACommandPair(SACommand([0xEE, 0x1, i]), SACommand([0xEE, 0x1, i])))

  def read_outputs(self):
    for i, name, resp in self.__read_device_name(0x4, 1, 128):
      if not resp[2] == 0:
        self.output[i] = Output(i, name, resp[2])

    return self.output

  def read_users(self):
    for i in range(1, 2):
      resp = self.connection.sendAuthenticatedCommand([0xE1], [i], debug=self.debug)

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
    time = f'{hours}:{minutes - hours * 60}'

    print(f'Date: {year}/{month}/{day} {time}')

    event_class = int_to_bit(event[1])[0:3]
    print(event_class_def[event_class])

    return event_index

  async def zones_violations(self):
    await self._transaction(SACommandPair(SACommand([0x00]), SACommand([0x00])))

  @property
  def zones_alarm(self):
    return get_set_bits(self.connection.sendCommand([0x02], debug=self.debug))

  @property
  def armed_partitions(self):
    """Really"""
    return get_set_bits(self.connection.sendCommand([0x0A], debug=self.debug))

  @property
  def partitions_alarm(self):
    return get_set_bits(self.connection.sendCommand([0x13], debug=self.debug))

  @property
  def partitions_fire_alarm(self):
    return get_set_bits(self.connection.sendCommand([0x14], debug=self.debug))

  @property
  def outputs_state(self):
    return get_set_bits(self.connection.sendCommand([0x17], debug=self.debug), is_hex=False)

  async def partitions_with_violates_zones(self):
    await self._transaction(SACommandPair(SACommand([0x25]), SACommand([0x25])))

  def new_state(self):
    # print get_set_bits(self.connection.sendCommand([0x07], debug=self.debug))
    print(get_set_bits(self.connection.sendCommand([0x7F], debug=self.debug), is_hex=False))

    print()
    for x in self.connection.sendCommand([0x7F], debug=self.debug):
      print(x)
      print(hex(x))

      print(int_to_bit(x), x)
    print()

  async def monitor(self):
    while True:
      await self.zones_violations()
      await self.partitions_with_violates_zones()
      await asyncio.sleep(5)

  async def arm(self, partition_list, mode=0):
    """Send arming command to the alarm. Modes allowed: from 0 till 3."""
    _parition_list = set_bits(int_list=partition_list, length=4)
    satel_cmd = 0x80

    cmd_ba = bytearray()
    cmd_ba.append(satel_cmd)
    cmd_ba.extend(self.usercode)
    cmd_ba.extend(_parition_list)

    await self._transaction(SACommandPair(SACommand(list(cmd_ba)), None))

  async def disarm(self, partition_list):
    """Send command to disarm."""
    _parition_list = set_bits(int_list=partition_list, length=4)
    satel_cmd = 0x84

    cmd_ba = bytearray()
    cmd_ba.append(satel_cmd)
    cmd_ba.extend(self.usercode)
    cmd_ba.extend(_parition_list)

    await self._transaction(SACommandPair(SACommand(list(cmd_ba)), None))

  async def clear_alarm(self, partition_list):
    """Send command to clear the alarm."""
    _parition_list = set_bits(int_list=partition_list, length=4)
    satel_cmd = 0x85

    cmd_ba = bytearray()
    cmd_ba.append(satel_cmd)
    cmd_ba.extend(self.usercode)
    cmd_ba.extend(_parition_list)

    await self._transaction(SACommandPair(SACommand(list(cmd_ba)), None))
