import React from 'react'
import ReactDOM from 'react-dom/client'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import App from './App.jsx'
import Overview from './pages/Overview.jsx'
import SiteDetail from './pages/SiteDetail.jsx'
import SocConsole from './pages/SocConsole.jsx'
import Alerts from './pages/Alerts.jsx'
import Applications from './pages/Applications.jsx'
import Settings from './pages/Settings.jsx'
import './index.css'

const router = createBrowserRouter([
  {
    path: '/',
    element: <App />,
    children: [
      { index: true, element: <Overview /> },
      { path: 'site/:name', element: <SiteDetail /> },
      { path: 'supervision', element: <SocConsole /> },
      { path: 'alertes', element: <Alerts /> },
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
