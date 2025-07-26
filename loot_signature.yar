rule AWS_Keys
{
  strings:
    $aws1 = /AKIA[0-9A-Z]{16}/
    $aws2 = /ASIA[0-9A-Z]{16}/
  condition:
    any of them
}

rule JWT_Tokens
{
  strings:
    $jwt = /eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/
  condition:
    $jwt
}