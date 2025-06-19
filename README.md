This is a static web server with jwt authentication enabled to protect resources.

The software is used for the techdoc project which requires only a static web server and implement simple way to authenticate users when required.

As of now only micro-gui techdoc might use it to serve US client but it is not in produdction yet.

When officially setup for US (that is exposing to the internet) we might need to ask Security Team if it is nessesary to audit this code. 
It should have the IP allowed list anyway when it happened.

The code here is trying to be as much simple as possible and only using golang standard library which is of high quality standard and passed any security 
auditing, maintained by Google Team.

The only exception if teh jwt library but that library is also the defacto standard in golang when handling jwt stuff.


Build

```
env CGO_ENABLED=0 go build -trimpath -ldflags="-X main.version=v0.1 -extldflags=-static -w -s" .
```

Run

```
env JWT_SECRET=myhighlysecret ./static-webserver-with-jwt
```

docker image per release is available. Try (add more option -e as appropriate, and the tag is the release version)
```
docker run --rm -p 8080:8080 -v $PWD:/www -e WEB_ROOT=/www -e JWT_SECRET=123 stevekieu/static-webserver-with-jwt:v0.6
```

The url will be http://localhost:8080/www/

Generate a valid jwt token go to https://jwt.io/ and geenrate one, use the secrets is the one you set when run the program.

Use it in curl command like this

```
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlN0ZXZlIERvZSIsImlhdCI6MTUxNjIzOTAyMn0.SrZbvVzwKiBP6D3OmpnWugYgE5AhH6XKUzyw_77AMq4" 'http://localhost:8080'
```

We can extend the expire token and verify username etc.

To set the expiry date- set the field 'exp' to a number (unix epoc)

Header

{
  "alg": "HS256",
  "typ": "JWT"
}

Payload 

{
  "sub": "1234567890",
  "name": "Steve Doe",
  "iat": 1516239022,
  "exp": 1718884803
}

