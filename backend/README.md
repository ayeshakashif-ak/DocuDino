
# 🦕 DocuDino Frontend

**DocuDino** is a modern, AI-powered web application designed for secure and efficient document verification. This is the frontend portion of the project, providing users with a seamless and intuitive experience.

---

## Features

- **Modern UI** — Responsive and user-friendly interface built with modern web technologies  
- **Secure Authentication** — User login, registration, and session handling  
- **AI-Powered Document Verification** — Intelligent analysis for document validation  
- **User Dashboard** — View and manage verified documents with analytics  
- **Clean Design** — Simple, elegant, and efficient UX  

---

## Security & Authentication

DocuDino implements robust security practices to protect user data and ensure reliable authentication:

- **JWT Tokens** — JSON Web Tokens are used for stateless and secure user authentication
- **Session Management** — Ensures persistent login sessions with proper token handling
- **Protected Routes** — React Router is used with guards to restrict access to authenticated users only
- **Token Refresh Strategy** — Handles token expiration gracefully (if implemented)
- **Secure Storage** — Sensitive tokens are stored securely in memory or via HttpOnly cookies (based on configuration)

> ✅ This ensures a secure, scalable, and user-friendly authentication system.

---

## 🧰 Tech Stack

- **React** — Component-based frontend framework  
- **TypeScript** — Strongly-typed JavaScript  
- **React Router** — Client-side routing  
- **Modern CSS** — Styled with custom CSS and utility-first design principles  

---

## 🚀 Getting Started

### ✅ Prerequisites

Ensure you have the following installed:

- [Node.js](https://nodejs.org/) (v14 or higher)
- npm or [Yarn](https://yarnpkg.com/)

### 🔧 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/REPO_NAME.git](https://github.com/ayeshakashif-ak/CY321-Semester-Project.git
   cd docudino-frontend
   ```

2. **Install dependencies**
   ```bash
   npm install
   # or
   yarn install
   ```

3. **Start the development server**
   ```bash
   npm run dev
   # or
   yarn dev
   ```

4. **Open in browser**

   Visit [http://localhost:5173](http://localhost:5173) to view the application.

---

## 📁 Project Structure

```
docudino-frontend/
├── public/                  # Static assets
├── src/
│   ├── components/          # Reusable components
│   │   ├── auth/            # Authentication-related UI
│   │   ├── common/          # General-purpose UI components
│   │   └── document/        # Document verification components
│   ├── contexts/            # React context providers
│   ├── pages/               # Page-level components
│   ├── styles/              # Global and component styles
│   └── App.tsx              # Main application entry
├── package.json             # Project metadata and scripts
└── README.md
```

---

## 📜 Available Scripts

| Command            | Description                       |
|--------------------|-----------------------------------|
| `npm run dev`      | Start the development server      |
| `npm run build`    | Build for production              |
| `npm run preview`  | Preview the production build      |

---

## 🤝 Contributing

We welcome contributions from the community!

- 🛠️ Fork the repository
- 🌱 Create a new branch (`git checkout -b feature/YourFeature`)
- ✅ Commit your changes (`git commit -m 'Add some feature'`)
- 📬 Push to the branch (`git push origin feature/YourFeature`)
- 🔄 Submit a Pull Request

Please make sure to follow the [Code of Conduct](CODE_OF_CONDUCT.md) and read our [Contributing Guidelines](CONTRIBUTING.md) if available.

---

## 📄 License

This project is licensed under the MIT License.  
See the [LICENSE](LICENSE) file for more information.

---

