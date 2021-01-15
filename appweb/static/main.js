function attachEvents(){

    var login = document.getElementById("login");
    login.addEventListener("change",validateLogin);

}

function validateLogin () {
    login = document.getElementById("login").value;
    if(login === ''){
        return false;
    }
    var letters = /^[a-z]+/;
    if(login.match(letters) === null || login.match(letters)[0] !== login){
            alert("Login musi się składać z samych znaków");
        return false;
    } else {
        return true;
    }
}

attachEvents();
