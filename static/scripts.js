
function togglePassword(id) {
	const field = document.getElementById(id);

	if (!field) return;  

	field.type = field.type === "password" ? "text" : "password";
}
