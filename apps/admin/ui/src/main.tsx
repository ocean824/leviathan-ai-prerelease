import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { AdminApp } from './AdminApp'
import { defaultAdminClient } from './runtime'
import './styles.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AdminApp client={defaultAdminClient} />
  </StrictMode>,
)
