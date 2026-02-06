import { useOutletContext } from "react-router-dom";
import SearchBar from "../../../components/keys/SearchBar";
import SearchResults from "../../../components/keys/SearchResults";
import FrequentlyUsedSection from "../../../components/keys/FrequentlyUsedSection";
import DepartmentsSection from "../../../components/keys/DepartmentsSection";
import DepartmentView from "../../../components/keys/DepartmentView";

const AllKeysPage = () => {
  const { 
    searchQuery, 
    setSearchQuery, 
    selectedDepartment,
    keys,
    frequentlyUsedKeys,
    usageCounts,
    handleRequestKey,
    handleReturnKey,
    handleDepartmentClick,
    handleBackToDepartments,
    handleToggleFrequent
  } = useOutletContext();

  return (
    <div className="flex-1 p-4 pb-20">
      {/* Global Search Bar */}
      <SearchBar 
        searchQuery={searchQuery} 
        setSearchQuery={setSearchQuery} 
      />

      {/* Global Search Results Section - Only show when outside departments/blocks and search is active */}
      {!selectedDepartment && searchQuery.trim() && (
        <SearchResults
          searchQuery={searchQuery}
          keys={keys}
          onRequestKey={handleRequestKey}
          onReturnKey={handleReturnKey}
          userRole="faculty"
        />
      )}

      {/* Department View */}
      {selectedDepartment ? (
        <DepartmentView
          department={selectedDepartment}
          keys={keys}
          searchQuery={searchQuery}
          onRequestKey={handleRequestKey}
          onToggleFrequent={handleToggleFrequent}
          onBack={handleBackToDepartments}
        />
      ) : (
        <>
          {!searchQuery.trim() && (
            <>
              <FrequentlyUsedSection
                keys={frequentlyUsedKeys}
                availabilityFilter="all"
                onRequestKey={handleRequestKey}
                usageCounts={usageCounts}
              />
              <DepartmentsSection
                keys={keys}
                onDepartmentClick={handleDepartmentClick}
                selectedDepartment={selectedDepartment}
              />
            </>
          )}
        </>
      )}
    </div>
  );
};

export default AllKeysPage;
