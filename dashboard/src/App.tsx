import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { FindingDetailPage } from './pages/FindingDetailPage'
import { HomePage } from './pages/HomePage'
import { PrFindingsPage } from './pages/PrFindingsPage'

export default function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/prs/:prId" element={<PrFindingsPage />} />
          <Route path="/prs/:prId/findings/:findingId" element={<FindingDetailPage />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}
