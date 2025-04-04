# Deployment Guide for Search Engine

This guide explains how to deploy the search engine application using Docker Compose.

## Prerequisites

- Docker and Docker Compose installed on your server
- Git installed on your server
- Domain name pointing to your server (optional for production)

## Deployment Steps

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd search_engine
```

### 2. Set Up Environment Variables

Create a `.env` file in the project root:

```bash
cp .env.example .env
```

Edit the `.env` file with your actual production values:

```bash
# Use a secure random string for the secret key
DJANGO_SECRET_KEY=your_secure_secret_key_here

# Database credentials
POSTGRES_DB=search_engine
POSTGRES_USER=postgres
POSTGRES_PASSWORD=secure_password_here

# Email settings
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your_email@gmail.com
EMAIL_HOST_PASSWORD=your_app_password_here

# Stripe settings (use production keys for production)
STRIPE_SECRET_KEY=sk_live_your_stripe_secret_key
STRIPE_PUBLIC_KEY=pk_live_your_stripe_public_key
STRIPE_WEBHOOK_SECRET=whsec_your_stripe_webhook_secret

# Frontend URL
FRONTEND_URL=https://your-frontend-domain.com
```

### 3. Build and Start the Application

For production:

```bash
docker-compose build
docker-compose up -d
```

### 4. Create Superuser (First Time Only)

```bash
docker-compose exec web python manage.py createsuperuser
```

Follow the prompts to create an admin user.

### 5. Access the Application

The application will be available at:

- Backend API: http://your-server-ip:8000/
- Admin panel: http://your-server-ip:8000/admin/

## Development Environment

For local development, use the development override file:

```bash
docker-compose -f docker-compose.yml -f docker-compose.override.yml up
```

This will:
- Use the development Dockerfile
- Mount your code as a volume for live reloading
- Run Django's development server instead of Gunicorn

## Maintenance

### View Logs

```bash
docker-compose logs -f web
```

### Restart Services

```bash
docker-compose restart web
```

### Update Application

```bash
git pull
docker-compose build web
docker-compose up -d
```

### Database Backup

```bash
docker-compose exec db pg_dump -U postgres search_engine > backup_$(date +%Y-%m-%d).sql
```

### Database Restore

```bash
cat backup_file.sql | docker-compose exec -T db psql -U postgres search_engine
```

## Security Considerations

1. Never commit `.env` files with real credentials to version control
2. For production, consider using a reverse proxy like Nginx for SSL termination
3. Regularly update dependencies and Docker images
4. Set up database backups on a regular schedule
5. Use strong, unique passwords for all services

## Troubleshooting

### Container Not Starting

Check the logs:

```bash
docker-compose logs web
```

### Database Connection Issues

Ensure the database container is running:

```bash
docker-compose ps
```

Check database logs:

```bash
docker-compose logs db
```

### Permission Errors

If you encounter permission errors with mounted volumes:

```bash
sudo chown -R $USER:$USER .
``` 