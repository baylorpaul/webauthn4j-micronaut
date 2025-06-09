import React from 'react'
import {createBrowserRouter, RouterProvider} from "react-router";
import GeneralHome from "./pages/GeneralHome.tsx";
import {LoginForm} from "./pages/Login.tsx";

const primaryRouter = createBrowserRouter([
	{
		children: [
			{ path: "/", Component: GeneralHome },
			{
				path: "/login",
				Component: LoginForm,
				children: [{ path: "*", Component: LoginForm }]
			},
		],
	},
]);

export default function App(): React.JSX.Element {
	return (
		<RouterProvider router={primaryRouter}/>
	);
}
