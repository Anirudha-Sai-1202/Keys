// Utility functions for formatting key-related data

/**
 * Get display label for category
 */
export const getCategoryLabel = (category) => {
  const categoryMap = {
    'classroom': 'Classroom',
    'lab': 'Lab',
    'office': 'Office',
    'storage': 'Storage',
    'library': 'Library',
    'auditorium': 'Auditorium',
    'cafeteria': 'Cafeteria',
    'hostel': 'Hostel',
    'maintenance': 'Maintenance',
    'security': 'Security',
    'staffroom': 'Staffroom',
    'other': 'Other'
  };
  return categoryMap[category] || category;
};

/**
 * Get display label for block
 */
export const getBlockLabel = (block) => {
  const blockMap = {
    'A': 'A Block',
    'B': 'B Block',
    'C': 'C Block',
    'D': 'D Block',
    'E': 'E Block',
    'F': 'F Block',
    'G': 'G Block',
    'H': 'H Block',
    'PG': 'PG Block',
    'MAIN': 'Main Building',
    'LIB': 'Library',
    'AUD': 'Auditorium',
    'CAF': 'Cafeteria',
    'HOSTEL': 'Hostel',
    'OTHER': 'Other'
  };
  return blockMap[block] || block;
};

/**
 * Get block information with description
 */
export const getBlockInfo = (block) => {
  const blockInfoMap = {
    'A': { name: 'A Block', description: 'Computer Science & Storage' },
    'B': { name: 'B Block', description: 'Physics & Chemistry Labs' },
    'C': { name: 'C Block', description: 'Biology & Research' },
    'D': { name: 'D Block', description: 'Library & Study Rooms' },
    'E': { name: 'E Block', description: 'Administration & Faculty' },
    'F': { name: 'F Block', description: 'Engineering Labs' },
    'G': { name: 'G Block', description: 'Workshops & Labs' },
    'H': { name: 'H Block', description: 'Research & Development' },
    'PG': { name: 'PG Block', description: 'Auditorium & Seminar Halls' },
    'MAIN': { name: 'Main Building', description: 'Administration & Offices' },
    'LIB': { name: 'Library', description: 'Library & Reading Rooms' },
    'AUD': { name: 'Auditorium', description: 'Auditorium & Event Halls' },
    'CAF': { name: 'Cafeteria', description: 'Cafeteria & Dining' },
    'HOSTEL': { name: 'Hostel', description: 'Hostel & Accommodation' },
    'OTHER': { name: 'Other', description: 'Other Facilities' }
  };
  return blockInfoMap[block] || { name: block, description: 'Other Facilities' };
};

/**
 * Get department label
 */
export const getDepartmentLabel = (department) => {
  const departmentMap = {
    'Accounts': 'Accounts',
    'Admission': 'Admission',
    'Automobile': 'Automobile',
    'CAMS': 'CAMS',
    'Chemistry': 'Chemistry',
    'Civil': 'Civil',
    'CSE': 'Computer Science Engineering',
    'CSE-AIML&IOT': 'CSE - AIML & IOT',
    'CSE-(CyS,DS)_and_AI&DS': 'CSE - (CyS, DS) and AI&DS',
    'Director': 'Director',
    'EEE': 'Electrical and Electronics Engineering',
    'ECE': 'Electronics and Communication Engineering',
    'EIE': 'Electronics and Instrumentation Engineering',
    'English': 'English',
    'GRO': 'GRO',
    'HR': 'Human Resources',
    'Humanity and sciences(H&S)': 'Humanity and Sciences (H&S)',
    'IQAC': 'IQAC',
    'IT': 'Information Technology',
    'MECH': 'Mechanical Engineering',
    'Other': 'Other',
    'PAAC': 'PAAC',
    'Placement': 'Placement',
    'Principal': 'Principal',
    'Purchase': 'Purchase',
    'RCC': 'RCC',
    'SSC': 'SSC',
    'VJ_Hub': 'VJ Hub'
  };
  return departmentMap[department] || department;
};
