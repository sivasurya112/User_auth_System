# Simple Authentication System (Login/Signup) using Node.js

This is a secure, responsive user authentication system built using **Node.js**, **Express**, **MongoDB**, and a custom **HTML/CSS/JS frontend**. It supports user registration, login, JWT-based session handling, password reset, password strength validation, and protected content routing.

---

## 🔧 Features

- ✅ User Signup with display name, username, and password
- ✅ Password strength validation (frontend & backend)
- ✅ Secure password hashing using bcrypt
- ✅ Login with JWT token generation
- ✅ Token-based access to protected routes
- ✅ Password reset via unique token
- ✅ Responsive UI using plain HTML, CSS, and JavaScript
- ✅ Clean logout and input clearing
- ✅ Password security rules explained visually
- ✅ Password reset token expiry and one-time usage
- ✅ MongoDB data persistence via Mongoose

---

## 🛠 Technologies Used

| Layer       | Stack                         |
|-------------|-------------------------------|
| Frontend    | HTML, CSS, JavaScript         |
| Backend     | Node.js, Express.js           |
| Database    | MongoDB (via Mongoose)        |
| Security    | JWT, bcrypt                   |
| Other Tools | VS Code, Postman, Git, GitHub |

---

## 📦 Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/auth-system-nodejs.git
cd auth-system-nodejs
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Environment Variables

Create a `.env` file in the root folder:
```
MONGO_URI=mongodb://localhost:27017/authdb
JWT_SECRET=your_jwt_secret_key
```

### 4. Run the App
```bash
node server.js
```

Go to:  
👉 `http://localhost:3000`

---

## 📸 Screenshots

- ✅ Sign-Up Page  
- ✅ Login Page  
- ✅ Password Reset Form  
- ✅ Protected Content View  

*(Screenshots can be added here as GitHub image links or inside a `/screenshots` folder.)*

---

## 🔐 Security Notes

- All passwords are hashed before storage using bcrypt.
- JWT tokens are signed with a secret key and expire after a set time.
- Password reset tokens are one-time use and expire after 15 minutes.
- `.env` is excluded from Git using `.gitignore`.

---

## 📌 Future Enhancements

- Email-based reset using Nodemailer
- Social login (Google, GitHub)
- Two-Factor Authentication (2FA)
- Admin dashboard for user management
- Logging & rate-limiting for added security

---

## 📄 License

This project is open-source and free to use under the [MIT License](LICENSE).

---

> Made with 💻 by SIVASURYA G
