import { QrCode } from "lucide-react";
import { useOutletContext } from "react-router-dom";

const QRScannerPage = () => {
  const { setShowScanner } = useOutletContext();
  return (
    <div className="flex-1 p-4 pb-20">
      {/* QR Scanner Section - Focused solely on scanning functionality */}
      <div className="text-center max-w-sm mx-auto mt-8 mb-8">
        <QrCode className="w-24 h-24 text-blue-400 mx-auto mb-6" />

        <h2 className="text-2xl font-bold text-white mb-4">QR Scanner</h2>
        <p className="text-gray-300 mb-8">
          Scan QR codes from faculty to approve key requests or returns
        </p>
        <button
          onClick={() => setShowScanner(true)}
          className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-4 rounded-xl font-semibold text-lg transition-colors flex items-center gap-3 mx-auto shadow-lg shadow-blue-500/30"
        >
          <QrCode className="w-6 h-6 text-blue-200" />
          Start Scanning
        </button>
      </div>
    </div>
  );
};


export default QRScannerPage;
