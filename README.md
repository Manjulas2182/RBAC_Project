# RBAC Project

## Overview
This project implements an **authentication and role-based access control (RBAC)** system using **Flask**, **JWT** for authentication, and **SQLAlchemy** for database management. It includes routes for **Admin**, **Moderator**, and **User** roles with protected access.

## Features
- **User Registration**: Allows users to register with a unique username, password, and role.
- **User Login**: Provides JWT token-based authentication for users.
- **Role-Based Routes**: Protected routes for Admin, Moderator, and User roles, each with specific access control.
- **JWT Authentication**: Uses JSON Web Tokens (JWT) for secure user authentication.
- **Role-Based Access Control (RBAC)**: Ensures that only users with the appropriate roles can access certain resources.

## Setup Instructions

### Prerequisites
- Python 3.x
- Flask==3.1.0
- Flask-JWT-Extended==4.7.1
- Flask-SQLAlchemy==3.1.1
- Werkzeug==3.1.3
- python-dotenv==1.0.1
- SQLAlchemy==2.0.36

### Installation
1. Clone the repository:

   ```bash
   git clone https://github.com/Manjulas2182/RBAC_Project.git
   cd RBAC
