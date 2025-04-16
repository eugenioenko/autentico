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
