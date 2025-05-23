<?php  
session_start();
$conn = null;
$demo = true;
include "../db_conn.php";

if ( !$demo && isset($_POST['username']) && isset($_POST['password']) && isset($_POST['role'] ) && isset($_POST['fullname']) ) {

	function test_input($data) {
	  $data = trim($data);
	  $data = stripslashes($data);
	  $data = htmlspecialchars($data);
	  return $data;
	}

    $fullname = test_input($_POST['fullname']);
	$username = test_input($_POST['username']);
	$password = test_input($_POST['password']);
	$role = test_input($_POST['role']);

	if (empty($username)) {
		header("Location: ../create-login.php?error=User Name is Required");
	}else if (empty($password)) {
		header("Location: ../create-login.php?error=Password is Required");
	}elseif (empty($fullname)) {
        header("Location: ../create-login.php?error=Full Name is Required");
    }
    else {

		// Hashing the password
		$password = md5($password);

        $table_name = "users";

        $root_folder = "/tmp";
        ####################################################################################################
        $sql = "SELECT * FROM ".$table_name." WHERE username='$username'";
        $result = mysqli_query($conn, $sql);

        $result_check = mysqli_num_rows($result);

        if ( $result_check === 1) {
            header("Location: ../create-login.php?error=User name already exist, pick a different one");
            die();
        }

        ####################################################################################################

        $c = uniqid (rand (),true);
        $folder = $root_folder."/".$c;

        $sql = "INSERT INTO ".$table_name." (username, password, role, name, folder) VALUES ( '".$username."', '".$password."', 'User', '".$fullname."', '".$folder."')";
        #$sql = "INSERT INTO MyGuests (firstname, lastname, email) VALUES ('John', 'Doe', 'john@example.com')";
        $result = mysqli_query($conn, $sql);

        if ( $result === TRUE)
        {
            #echo "New record created successfully";
        } else {
            echo "Error: " . $sql . "<br>" . mysqli_error($conn);
            die();
        }

        $sql = "SELECT * FROM ".$table_name." WHERE username='$username' AND password='$password'";
        $result = mysqli_query($conn, $sql);

        if( !$result )
            header("Location: ../create-login.php?error=Incorrect User name or password");

        $result_check = mysqli_num_rows($result);



        if ( $result_check === 1) {
        	// the user name must be unique
        	$row = mysqli_fetch_assoc($result);
        	if ($row['password'] === $password && $row['role'] == $role)
            {
        		$_SESSION['name'] = $row['name'];
        		$_SESSION['id'] = $row['id'];
        		$_SESSION['role'] = $row['role'];
        		$_SESSION['username'] = $row['username'];
                $_SESSION['folder'] = $row['folder'];

                $user_directory = $_SESSION['folder'];
                if( $user_directory === "null")
                {
                    $c = uniqid (rand (),true);
                    $user_directory = $root_folder."/".$c;
                    $sql = "UPDATE ".$table_name." SET folder = '".$user_directory."' WHERE username='".$_SESSION['username']."'";
                    $result = mysqli_query($conn, $sql);
                    $_SESSION['folder'] = $user_directory;
                }
                if (!file_exists($user_directory) )
                {
                    mkdir($user_directory, 0777, true);
                }
                $file = $user_directory.'/.panconfkeystore';
                if(!is_file($file)){
                    $contents = '';           // Some simple example content.
                    file_put_contents($file, $contents);     // Save our content to the file.
                }

        		header("Location: ../home.php");

        	}else {
        		header("Location: ../create-login.php?error=User name already exist, pick a different one");
        	}
        }else {
        	header("Location: ../create-login.php?error=User name already exist, pick a different one");
        }

	}
	
}else {
	header("Location: ../index.php");
}