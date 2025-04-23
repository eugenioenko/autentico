todos

- add logger
- add validation

register

```bash
curl -X POST http://localhost:8080/users/create -H "Content-Type: application/json" -d '{"username": "testuser@email.com", "email": "testuser@email.com", "password": "password123"}'
 curl -X POST http://localhost:8080/users/create -H "Content-Type: application/json" -d '{"username": "user@email.com", "email": "user@email.com", "password": "kdok382k!"}'
```

login

```bash
curl -X POST http://localhost:8080/api/v1/users/login -H "Content-Type: application/json" -d '{"username": "testuser@email.com", "password": "password123"}'
```

/authorize

```bash
curl -G http://localhost:8080/oauth2/authorize \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=your-client-id" \
  --data-urlencode "redirect_uri=https://your-client-app.com/callback" \
  --data-urlencode "scope=openid profile email" \
  --data-urlencode "state=xyz123" \
  --data-urlencode "code_challenge=your-code-challenge" \
  --data-urlencode "code_challenge_method=S256"
```

http://localhost:8080/oauth2/authorize?response_type=code&client_id=&state=something&scope=read&redirect_uri=https%3A%2F%2Foauth.pstmn.io%2Fv1%2Fcallback

/token

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=FVoVDDCzpLiiWiiWW1sV6qn7pSj5eaD_0WWpxtV2y1M" \
  -d "redirect_uri=https://your-client-app.com/callback" \
  -d "client_id=your-client-id"
```
