
# Incident-Response-Platform

## 🚨 Project Overview

The **Incident-Response-Platform** is a cybersecurity tool designed to manage and respond to security alerts effectively. It consists of:

- **Django Web Application** – Frontend and backend for managing incidents.
- **Webhook** – Receives and processes alerts from Wazuh.
- **Database** – Stores alerts and incident response data for analysis.

---

## ⚙️ Installation and Setup Guide

### 1. Install MySQL on Linux

**Connect to MySQL:**
```bash
mysql -u root
```

**Create a User:**
```sql
CREATE USER 'username'@'allowed_ip_address' IDENTIFIED BY 'YourVerySecretPassword';
```

> Use `%` as `allowed_ip_address` to allow access from any IP.

**Grant Privileges:**
```sql
GRANT ALL PRIVILEGES ON your_database_name.* TO 'username'@'allowed_ip_address';
FLUSH PRIVILEGES;
```

---

### 2. Clone the Repository

```bash
git clone [REPOSITORY_URL]
cd Incident-Response-Platform
```

---

### 3. Create a Virtual Environment

#### On Windows:
```bash
python3 -m venv venv
venv\Scripts\activate
```

#### On Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

---

### 4. Install System Packages (Linux only)

```bash
sudo apt update
sudo apt install build-essential pkg-config python3-dev default-libmysqlclient-dev
```

---

### 5. Install Python Dependencies

```bash
pip install -r requirements.txt
```

---

### 6. Configure the Database

Edit `settings.py` in your Django project and set the MySQL database connection info:

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'your_database_name',
        'USER': 'username',
        'PASSWORD': 'YourVerySecretPassword',
        'HOST': 'localhost',  # or the IP address
        'PORT': '3306',
    }
}
```

---

### 7. Run Database Migrations

```bash
python manage.py migrate
```

---

### 8. (Optional) Enable AI Features

To use chatbot/AI features, install **Ollama** and serve the **Mistral 7B** model.

- [Download Ollama](https://ollama.ai)
- Start the model:

```bash
ollama serve
```

---

### 9. Start the Application

```bash
python manage.py runserver
```

---

### 10. Create a Superuser

```bash
python manage.py createsuperuser
```

Follow the prompts to set up an admin account.

---

### 11. User Management

- Use the registration page to allow users to create accounts.
- Superusers can manage users and incidents from the Django admin panel.

---

## 🖼️ Screenshots

| Login | Register | Dashboard |
|-------|----------|-----------|
| ![Login](images/cap1_login.png) | ![Register](images/cap2_register.png) | ![Dashboard](images/cap3_Dashboard.png) |

| Incident Response | Case Management | Chatbot |
|-------------------|------------------|---------|
| ![Incident Response](images/cap4_incident_Response.png) | ![Case](images/cap5_case.png) | ![Chatbot](images/cap6_chatbot.png) |

---

## 🤝 Contributions

Contributions are welcome! Feel free to submit a pull request or open an issue with suggestions and improvements.

---

## 📄 License

This project is licensed under the USTHB.

---
