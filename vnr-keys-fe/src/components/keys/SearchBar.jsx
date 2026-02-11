import { Search } from "lucide-react";

const SearchBar = ({ searchQuery, setSearchQuery }) => {
  return (
    <div className="mb-6">
      <div className="relative group">
        {/* Icon */}
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-indigo-400 w-5 h-5 transition-colors duration-300 group-hover:text-indigo-300" />

        {/* Input */}
        <input
          type="text"
          placeholder="Search keys..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full bg-gray-800 border border-gray-700 rounded-xl pl-10 pr-4 py-3 
            text-white placeholder-gray-400
            focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent
            transition-all duration-500
            group-hover:shadow-[0_0_15px_rgba(99,102,241,0.5)]"
        />
      </div>
    </div>
  );
};

export default SearchBar;
