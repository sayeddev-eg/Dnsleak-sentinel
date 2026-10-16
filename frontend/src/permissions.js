const ALL = ["admin", "analyst", "viewer"]
const STAFF = ["admin", "analyst"]
const ADMIN = ["admin"]

export const permissions = {
  viewKpi: ALL,
  viewCharts: ALL,
  viewModelStatus: ALL,
  viewTopDevices: STAFF,
  viewAlerts: STAFF,
  viewDetails: STAFF,
  useInspector: STAFF,
  uploadPcap: STAFF,
  runSimulator: ADMIN,
  clearLogs: ADMIN,
  exportData: ADMIN,
  manageUsers: ADMIN,
}

export const can = (role, feature) => (permissions[feature] || []).includes(role)
