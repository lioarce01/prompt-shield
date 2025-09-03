# SSL Certificates Directory

This directory is for SSL certificates used by the Nginx reverse proxy in production mode.

## Setup for Production

1. **Generate self-signed certificates for testing:**
```bash
# Generate private key
openssl genrsa -out key.pem 2048

# Generate certificate
openssl req -new -x509 -key key.pem -out cert.pem -days 365
```

2. **For production, use Let's Encrypt or your certificate authority:**
```bash
# Example with certbot (Let's Encrypt)
certbot certonly --standalone -d your-domain.com
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem cert.pem
cp /etc/letsencrypt/live/your-domain.com/privkey.pem key.pem
```

3. **Required files:**
- `cert.pem` - SSL certificate
- `key.pem` - Private key

## Security Notes

- Never commit actual certificates to version control
- Set proper file permissions (600 for private key)
- Use strong certificates in production
- Regularly renew certificates

## Docker Usage

The nginx service will mount this directory as:
```yaml
volumes:
  - ./ssl:/etc/ssl/certs:ro
```

Make sure your certificates are named `cert.pem` and `key.pem`.