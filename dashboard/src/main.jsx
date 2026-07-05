import React from 'react'
import ReactDOM from 'react-dom/client'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import App from './App.jsx'
import SiteStatus from './pages/SiteStatus.jsx'
import SocConsole from './pages/SocConsole.jsx'
import Applications from './pages/Applications.jsx'
import Settings from './pages/Settings.jsx'
import './index.css'

const router = createBrowserRouter([
  {
    path: '/',
    element: <App />,
    children: [
      { index: true, element: <SiteStatus /> },
      { path: 'supervision', element: <SocConsole /> },
      { path: 'applications', element: <Applications /> },
      { path: 'parametres', element: <Settings /> },
    ],
  },
])

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>,
)
