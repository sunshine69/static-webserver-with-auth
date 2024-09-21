This is a static web server with jwt authentication enabled to protect resources.


Testing ...

Build

```
env CGO_ENABLED=0 go build -trimpath -ldflags="-X main.version=v0.1 -extldflags=-static -w -s" .
```

Run like this. Notice that we use relative path to the current working directory. If you want to have absolute path - set it in WEB_ROOT, but PUBLIC_ROOT should be relative to WEB_ROOT to avoid route conflict.

```
env JWT_SECRET=abc AUTH_TYPE=auto SECURE_COOKIE=false WEB_ROOT=./Private PUBLIC_ROOT=./Public go run .
```

docker image per release is available. Try (add more option -e as appropriate, and the tag is the release version)
```
docker run --rm -p 8080:8080 -v $PWD:/www -e WEB_ROOT=/www -e JWT_SECRET=123 stevekieu/static-webserver-with-jwt:v0.6
```

The url will be http://localhost:8080/www/

Generate a valid jwt token go to https://jwt.io/ and generate one, use the secrets is the one you set when run the program.

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

