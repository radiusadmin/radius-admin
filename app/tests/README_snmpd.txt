SNMP poller tests (tests/test_snmp.py) need a test agent on 127.0.0.1:161. Port 161 needs
root, and the app suite runs as the postgres OS user, so start the agent first as root
(sandbox only, never on the production server):

  apt install snmp snmpd
  D=$(mktemp -d); mkdir $D/persist
  printf 'rouser radmon authpriv .1\nsysName test-switch-01\nsysDescr Test agent\ncreateUser radmon SHA-256 "AuthPass-Test-1" AES "PrivPass-Test-2"\n' > $D/snmpd.conf
  snmpd -C -c $D/snmpd.conf -p $D/pid --persistentDir=$D/persist -Lf $D/log udp:127.0.0.1:161

Stop it afterwards with: kill $(cat $D/pid)
