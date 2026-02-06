// LoadingKeys.jsx
import React from "react";

const LoadingKeys = () => {
  return (
    <div className="w-full h-screen flex flex-col justify-center items-center bg-white">
      {/* Key animation */}
      <div className="w-24 h-24 relative">
        <div className="absolute w-24 h-24 border-4 border-blue-400 rounded-full animate-spin"></div>
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-blue-600 font-bold text-lg">
          🔑
        </div>
      </div>
      <p className="mt-4 text-gray-700 text-lg">Loading keys...</p>
    </div>
  );
};

export default LoadingKeys;
