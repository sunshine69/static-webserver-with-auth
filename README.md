Generate a valid jwt token go to https://jwt.io/ and geenrate one, use the secrets is `secret-key-for-jwt`.

Use it in curl command like this

curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlN0ZXZlIERvZSIsImlhdCI6MTUxNjIzOTAyMn0.SrZbvVzwKiBP6D3OmpnWugYgE5AhH6XKUzyw_77AMq4" 'http://localhost:8080'

We can extend the expire token and verify username etc.

To set the expiry date- set teh field 'exp' to a number (unix epoc)

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

