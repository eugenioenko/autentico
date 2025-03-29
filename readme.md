register

```bash
curl -X POST http://localhost:8080/create -H "Content-Type: application/json" -d '{"username": "testuser@email.com", "email": "testuser@email.com", "password": "password123"}'
```

login

```bash
curl -X POST http://localhost:8080/login -H "Content-Type: application/json" -d '{"username": "testuser@email.com", "password": "password123"}'
```
