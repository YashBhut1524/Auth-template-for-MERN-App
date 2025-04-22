import { Outlet } from 'react-router-dom';

function App() {
  return (
    <div>
      <div className="p-6 bg-red-500 h-10">
        {/* Your header or navbar */}
      </div>
      <Outlet /> {/* This is where child routes will be rendered */}
    </div>
  );
}

export default App;
