import React from "react";
import {useNavigate} from "react-router";

export default function GeneralHome(): React.JSX.Element {

	const navigate = useNavigate();

	React.useEffect(
		() => {
			navigate('/login');
		},
		[]
	);

	return (<></>);
}
