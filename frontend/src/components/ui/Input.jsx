const Input = ({ icon: Icon, error, ...props }) => {
	const hasError = !!error;

	return (
		<div className='relative mb-6'>
			<div className='absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none'>
				<Icon className={`size-5 ${hasError ? 'text-red-500' : 'text-green-500'}`} />
			</div>
			<input
				{...props}
				className={`w-full pl-10 pr-3 py-2 bg-gray-800 bg-opacity-50 rounded-lg border transition duration-200 text-white placeholder-gray-400 ${
					hasError
						? 'border-red-500 focus:border-red-500 focus:ring-2 focus:ring-red-500'
						: 'border-gray-700 focus:border-green-500 focus:ring-2 focus:ring-green-500'
				}`}
			/>
			{hasError && (
				<p className='mt-1 text-sm text-red-500'>{error}</p>
			)}
		</div>
	);
};
export default Input;
