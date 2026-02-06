import React from "react";

const KeySVG = ({ className = "" }) => (
	<svg className={className} width="80" height="80" viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
		<g filter="url(#glow)">
			<circle cx="40" cy="40" r="36" fill="#22c55e" fillOpacity="0.15" />
		</g>
		<path d="M55 35a10 10 0 1 0-7.07 7.07L60 54v4a2 2 0 0 0 2 2h4a2 2 0 0 0 2-2v-4h2a2 2 0 0 0 2-2v-4a2 2 0 0 0-2-2h-4l-5.07-5.07A10 10 0 0 0 55 35ZM35 35a5 5 0 1 1 10 0 5 5 0 0 1-10 0Z" fill="#22c55e" stroke="#16a34a" strokeWidth="2" />
		<defs>
			<filter id="glow" x="0" y="0" width="80" height="80" filterUnits="userSpaceOnUse" colorInterpolationFilters="sRGB">
				<feGaussianBlur stdDeviation="8" result="coloredBlur" />
				<feMerge>
					<feMergeNode in="coloredBlur" />
					<feMergeNode in="SourceGraphic" />
				</feMerge>
			</filter>
		</defs>
	</svg>
);

const AnimatedLoader = ({ loading = true, error = false, onRetry }) => {
	return (
		<div className={`w-full h-screen flex flex-col justify-center items-center ${error ? 'bg-red-600' : 'bg-green-600'} relative transition-colors duration-500`}>
			{/* Animated top-left circle */}
			<div className="absolute left-0 top-0 m-6">
				<div
					className={`w-20 h-20 rounded-full ${error ? 'bg-red-400 animate-pulse' : 'bg-green-400 animate-spin-slow'} shadow-lg`}
					style={{ boxShadow: error ? '0 0 40px 10px #ef4444' : '0 0 40px 10px #22c55e' }}
				></div>
			</div>
			{/* Center animated key */}
			<div className="flex flex-col items-center justify-center mt-12">
				<div className="mb-4">
					{error ? (
						<span className="text-6xl">⚠️</span>
					) : (
						<div className="animate-bounce-slow">
							<KeySVG />
						</div>
					)}
				</div>
				<p className="text-white text-xl font-bold mb-2">
					{error ? 'Network Error' : 'Loading keys...'}
				</p>
				<p className="text-white text-md mb-6">
					{error
						? 'Unable to load keys. Please check your connection.'
						: 'Please wait while we fetch your data.'}
				</p>
				{error && (
					<button
						className="bg-white text-red-600 font-semibold px-6 py-2 rounded-lg shadow hover:bg-red-100 transition-colors"
						onClick={onRetry}
					>
						Retry
					</button>
				)}
			</div>
			{/* Add custom animation classes to tailwind.config.js:
				animation: {
					'spin-slow': 'spin 2s linear infinite',
					'bounce-slow': 'bounce 2s infinite',
				},
			*/}
		</div>
	);
};

export default AnimatedLoader;
