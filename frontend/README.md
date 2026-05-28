# AICDS Frontend - AI Cybersecurity Defense System

A professional Security Operations Center (SOC) dashboard built with React and TypeScript. This frontend provides real-time threat detection, anomaly analysis, and comprehensive security log management for enterprise cybersecurity operations.

## 🎯 Overview

The AICDS Frontend is a modern, responsive web application designed to help security teams monitor, detect, and respond to cyber threats in real-time. With an intuitive interface and powerful analytics, operators can quickly identify and mitigate security incidents.

## ✨ Features

### 🔐 **Authentication & Security**
- Secure operator login with JWT tokens
- User registration with validation
- Session persistence using localStorage
- Automatic token expiration handling (401 redirects to login)
- Private route protection for dashboard access
- Logout functionality with session cleanup

### 📊 **Dashboard & Analytics**
- Real-time metrics cards showing statistics
- Interactive charts:
  - **Bar Chart**: Traffic trend analysis
  - **Pie Chart**: Traffic distribution visualization
  - **Line Chart**: Threat intensity over time
- Recent activity feed with threat status indicators
- Live system status indicators with real-time health checks

### 🎯 **Threat Detection**
- URL-based threat analysis interface
- Real-time scanning with background polling
- Confidence scoring system
- Risk level indicators
- Detailed threat results with AI reasoning
- Toast notifications for scan completion

### 🔍 **Anomaly Detection**
- Network-based anomaly detection
- NSL-KDD format support with 41+ features
- Behavioral analysis with anomaly scoring
- Severity level classification
- Pattern recognition indicators

### 📋 **Advanced Logs System**
- Comprehensive log viewing and management
- Real data integration from backend
- **Filtering capabilities**: By verdict type
- **Sorting options**: By timestamp, status
- **Export functionality**: Download logs as CSV
- Detailed modal view with report data
- ERROR verdict styling for visual distinction
- Real-time log updates from backend

### 🎨 **UI/UX Features**
- Professional dark cybersecurity theme with blue accent
- Glass morphism design effects
- Smooth animations and transitions
- Responsive design (mobile, tablet, desktop)
- Pulse glow animations for alerts
- Loading spinners and error states
- Toast notifications for user feedback
- Mobile-responsive sidebar with overlay menu

### 🔌 **API Integration**
- Axios-based HTTP client with JWT interceptor
- Configurable API base URL
- Automatic 401 token expiration handling
- Error handling and response interceptors
- Loading states during API calls
- Trailing-slash fixing for backend compatibility

## 🏗️ Tech Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| **Frontend Framework** | React | 18.2.0 |
| **Language** | TypeScript | 5.0.0 |
| **Build Tool** | Vite | 5.4.21 |
| **Styling** | Tailwind CSS | 3.4.0 |
| **Routing** | React Router DOM | 6.22.0 |
| **HTTP Client** | Axios | 1.6.0 |
| **Charts** | Recharts | 2.10.0 |
| **Icons** | Lucide React | 0.366.0 |
| **CSS Processing** | PostCSS, Autoprefixer | 8.4.0, 10.4.0 |

## 📦 Installation

### Prerequisites
- **Node.js**: v16 or higher
- **npm**: v7 or higher (or yarn/pnpm)

### Setup Instructions

1. **Clone the repository**
```bash
git clone https://github.com/Ola-09/aicds-frontend.git
cd aicds-frontend
```

2. **Install dependencies**
```bash
npm install --legacy-peer-deps
```
> Note: Using `--legacy-peer-deps` to resolve peer dependency conflicts between React 18 and lucide-react

3. **Set up environment variables**
```bash
# Create .env.local file
VITE_API_BASE_URL=http://localhost:8000/api/v1
```

4. **Start the development server**
```bash
npm run dev
```

The application will be available at `http://localhost:5173/`

## 🚀 Deployment

### Vercel Deployment

This project is optimized for deployment on [Vercel](https://vercel.com/).

#### Prerequisites
- GitHub repository with this code
- Vercel account (free tier available)

#### Automatic Deployment Setup

1. **Connect Repository to Vercel**
   - Go to [Vercel Dashboard](https://vercel.com/dashboard)
   - Click "Add New..." → "Project"
   - Import your GitHub repository
   - Select the `aicds-frontend` directory as the root

2. **Configure Project**
   - **Framework**: Vite
   - **Build Command**: `npm run build` (default)
   - **Output Directory**: `dist`
   - **Install Command**: `npm install --legacy-peer-deps`

3. **Set Environment Variables**
   In the Vercel dashboard, add:
   ```
   VITE_API_BASE_URL=https://aicds-backend.onrender.com/api/v1
   ```
   (Replace with your actual backend URL)

4. **Deploy**
   - Click "Deploy"
   - Vercel will automatically build and deploy your project
   - Your frontend will be live at `https://<your-project>.vercel.app`

#### Manual Deployment via Vercel CLI

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel

# For production deployment
vercel --prod
```

#### Environment Variables for Production
```
VITE_API_BASE_URL=https://your-backend-domain.com/api/v1
```

---

## 📖 Development

### Available Scripts

```bash
# Start development server with HMR
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview

# Run TypeScript type checking
npx tsc --noEmit

# Run ESLint checks
npm run lint
```

### Project Structure

```
src/
├── components/              # Reusable UI components
│   ├── Navbar.tsx          # Top navigation bar with real-time system health
│   ├── Sidebar.tsx         # Left sidebar navigation with admin retrain button
│   ├── Card.tsx            # MetricCard and SimpleCard components
│   ├── Table.tsx           # Dynamic table component with custom rendering
│   ├── DetectionForm.tsx   # Shared form for detection pages (NSL-KDD support)
│   ├── LoadingState.tsx    # LoadingSpinner, ErrorState, WarningState
│   └── PrivateRoute.tsx    # Route protection component
│
├── context/                # React Context for state management
│   ├── AuthContext.tsx     # Authentication state, token management, login/logout
│   └── ThemeContext.tsx    # Theme management
│
├── pages/                  # Page components
│   ├── Dashboard.tsx       # Main dashboard with metrics, charts, and real logs
│   ├── Login.tsx           # Blue-themed secure login page
│   ├── Register.tsx        # User registration page
│   ├── ThreatDetection.tsx # URL-based threat analysis interface
│   ├── AnomalyDetection.tsx # Network anomaly detection interface
│   ├── UrlScan.tsx         # Dedicated URL scan page with background polling
│   └── Logs.tsx            # Log management with backend data integration
│
├── services/               # API clients and utilities
│   └── api.ts              # Axios HTTP client with JWT interceptor and 401 handling
│
├── App.tsx                 # Main application component with routing
├── App.css                 # Application styles
├── index.css               # Global styles & Tailwind directives
└── main.tsx                # Application entry point
```

## 🔐 Authentication Flow

1. **Unauthenticated users** → Redirected to `/login` page
2. **Login page** accepts any non-empty username/password (demo mode)
3. **Successful login** → Redirected to `/` (Dashboard)
4. **Session persistence** → User data stored in localStorage
5. **Logout button** in navbar → Clears session and redirects to login
6. **Page refresh** → Session persists if saved in localStorage

**Demo Credentials:**
```
Username: admin
Password: password123
(Any non-empty combination works in development)
```

## 🎮 Usage

### Dashboard Page `/`
- View real-time metrics and KPIs
- Interact with trend charts
- Monitor system status and recent activities

### Threat Detection Page `/detect`
- Analyze potential threats
- Upload files for scanning
- View confidence scores and risk assessment

### Anomaly Detection Page `/anomaly`
- Detect behavioral anomalies
- View anomaly severity scores
- Monitor pattern changes

### Logs Page `/logs`
- View all security events
- Filter by log type
- Sort chronologically
- Export data as CSV
- View summary statistics

## 🔌 Backend Integration

### API Endpoint Configuration
Update the API base URL in `src/services/api.ts`:

```typescript
const API_BASE_URL = 'http://localhost:8000'; // Change as needed
```

### Expected Backend Endpoints

**POST `/api/threat-detection/detect`**
```json
Request Body:
{
  "analysis": "suspicious network traffic",
  "file": "optional_file_content"
}

Response:
{
  "riskLevel": "HIGH",
  "confidence": 0.95,
  "threats": ["malware", "port scanning"]
}
```

**POST `/api/anomaly-detection/detect`**
```json
Request Body:
{
  "behavior": "unusual_login_pattern",
  "metrics": {...}
}

Response:
{
  "anomalyScore": 0.87,
  "severity": "HIGH",
  "description": "Anomaly detected"
}
```

## 🛠️ Customization

### Styling & Theme

- **Colors**: Customize in `tailwind.config.js`
- **Animations**: Edit keyframes in `src/index.css`
- **Dark Theme**: Default dark cybersecurity color scheme
  - Primary Red: `#ef4444`
  - Success Green: `#22c55e`
  - Warning Yellow: `#eab308`
  - Info Blue: `#3b82f6`
  - Accent Purple: `#a855f7`

### Adding New Pages

1. Create a new component in `src/pages/`
2. Add the route in `src/App.tsx`
3. Add navigation link in `src/components/Sidebar.tsx`

## 📱 Browser Support

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)
- Mobile browsers (iOS Safari, Chrome Mobile)

## 🐛 Troubleshooting

### Port 5173 already in use
```bash
# Kill process on port 5173 or use alternate port
npm run dev -- --port 3000
```

### Module not found errors
```bash
# Clear node_modules and reinstall
rm -rf node_modules
npm install --legacy-peer-deps
```

### Hot Module Replacement (HMR) not working
- Ensure dev server is running
- Clear browser cache (Ctrl+Shift+Delete)
- Restart dev server: `npm run dev`

## 📝 Environment Variables

Create a `.env.local` file for environment-specific settings:

```env
VITE_API_BASE_URL=http://localhost:8000
VITE_APP_NAME=AICDS
VITE_APP_VERSION=1.0.0
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💻 Authors

- **Development Team** - AICDS Project

## 🔗 Related Projects

- **Backend**: AICDS FastAPI Backend (https://github.com/Ola-09/aicds-backend)
- **Documentation**: AICDS Docs

## 📞 Support

For support, please open an issue on the GitHub repository or contact the development team.

## 🚀 Future Enhancements

- [ ] Real-time WebSocket integration for live updates
- [ ] Advanced filtering and search capabilities
- [ ] Custom dashboard configurations
- [ ] Multi-user role-based access control (RBAC)
- [ ] Dark/Light theme toggle
- [ ] Mobile app version
- [ ] Email alerts and notifications
- [ ] Integration with SIEM systems
- [ ] Machine learning-based threat prediction
- [ ] API documentation and OpenAPI integration

---

**Last Updated**: March 2026  
**Version**: 0.0.0

import reactDom from 'eslint-plugin-react-dom'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      // Other configs...
      // Enable lint rules for React
      reactX.configs['recommended-typescript'],
      // Enable lint rules for React DOM
      reactDom.configs.recommended,
    ],
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.node.json', './tsconfig.app.json'],
        tsconfigRootDir: import.meta.dirname,
      },
      // other options...
    },
  },
])
```
