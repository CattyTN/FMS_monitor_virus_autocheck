/*
var btnUpload = $("#upload_file"),
    btnOuter = $(".button_outer");

btnUpload.on("change", function (e) {
    var ext = btnUpload.val().split('.').pop().toLowerCase();
    if ($.inArray(ext, ['gif', 'png', 'jpg', 'jpeg', 'pcap']) == -1) {
        $(".error_msg").text("Invalid file format...");
    } else {
        $(".error_msg").text("");
        btnOuter.addClass("file_uploading");
        setTimeout(function () {
            btnOuter.addClass("file_uploaded");
        }, 3000);
        var uploadedFile = URL.createObjectURL(e.target.files[0]);
        setTimeout(function () {
            $("#uploaded_view").append('<img src="' + uploadedFile + '" />').addClass("show");
        }, 3500);
    }
});

*/
/*

$(".file_remove").on("click", function (e) {
    $("#uploaded_view").removeClass("show");
    $("#uploaded_view").find("img").remove();
    btnOuter.removeClass("file_uploading");
    btnOuter.removeClass("file_uploaded");
});
*/

window.addEventListener('load', function(){
    submit_click()
})

function submit_click(){
    var e = document.getElementsByClassName("text-secondary font-weight-bold text-xs submit-button")
    for (var i = 0; i < e.length; i++) {
        e[i].addEventListener('click', function () {
                // Lấy id của nút được click và gán vào biến dataset_name

                var dataset_name = $(this).attr('id');
                // Gửi yêu cầu AJAX với dataset_name
                $.ajax({
                    type: 'POST',
                    url: '/test',
                    data: {
                        dataset_name: dataset_name
                    },
                    success: function(response) {
                        if(response == 1){
                            Swal.fire({
                                title: 'Phát hiện tấn công!!',
                                text: "Luồng dữ liệu độc hại!",
                                icon: 'warning',
                                showCancelButton: true,
                                confirmButtonText: 'Chi tiết!',
                                cancelButtonText: 'Ok!',
                                reverseButtons: true
                                }).then((result) => {
                                    if (result.isConfirmed) {
                                        var dataset_name_2 = dataset_name; 
                                        redirectToDetailsPage(dataset_name_2);

                                    } else if (result.dismiss === Swal.DismissReason.cancel) {
                                        window.location.href = '/tables'
                                    }
                                  })
                        }
                        else{
                            Swal.fire({
                                title: 'Bình thường!!',
                                text: "Luồng dữ liệu lành tính!",
                                icon: 'success',
                                showCancelButton: false,
                                confirmButtonText: 'OK!',
                                reverseButtons: true
                                }).then((result) => {
                                    if (result.isConfirmed) {
                                        window.location.href = '/tables'
                                    } 
                                  })
                        }
                    
                        // Thực hiện lệnh JavaScript sau khi nhận được giá trị a
                        
                        // Thực hiện chuyển hướng đến route "/tables" trong Flask
                        
                    },
                    error: function(error) {
                        console.error(error);
                    }
                }); 
        })
    }
}

function redirectToDetailsPage(dataset_name) {
    // Tạo một biểu mẫu ẩn
    var form = document.createElement("form");
    form.method = "post";
    form.action = "/details";

    // Tạo một input ẩn để truyền dữ liệu
    var input = document.createElement("input");
    input.type = "hidden";
    input.name = "flow_name";
    input.value = dataset_name;

    // Thêm input vào biểu mẫu
    form.appendChild(input);

    // Thêm biểu mẫu vào trang và tự động gửi yêu cầu
    document.body.appendChild(form);
    form.submit();
}


window.addEventListener('load', function(){
    upload_file_to_flows()
})

function upload_file_to_flows(){
    var e = document.getElementById("upload_file")
    if(e){
        e.addEventListener('change', function (){
            var selected_file = e.files[0]
            var full_file_name = selected_file.name.toString()
            $.ajax({
                type: 'POST',
                url: '/upload_file_to_flows',
                data: {
                    a: full_file_name
                },
                success: function(response) {
                    if(response.toString() == "1"){
                        Swal.fire({
                            title: 'Thành công!!',
                            text: "Upload flow dữ liệu thành công!",
                            icon: 'success',
                            showCancelButton: false,
                            confirmButtonText: 'OK!',
                            reverseButtons: true
                            }).then((result) => {
                                if (result.isConfirmed) {
                                    window.location.href = '/tables'
                                } 
                              })
                    }
                    else{
                        Swal.fire(
                            'Không thành công!',
                            'Flow đã tồn tại!',
                            'warning'
                          );
                    }
    
                },
                error: function(error) {
                    console.log("error");
                }
            }); 
        })
    }
    
}

window.addEventListener('load', function(){
    capture_button_listen()
})

function capture_button_listen(){
    var e = document.getElementById("captureButton")
    if (e){
        e.addEventListener('click', function(){
            var selectElement = document.getElementById("inputGroupSelect01");
            var selectedValue = selectElement.value;
            $.ajax({
                type: 'POST',
                url: '/capture_extract',
                data: {
                    interface_name: selectedValue
                },
                success: function(response) {
    
                },
                error: function(error) {
                    console.log("error");
                }
            }); 
        })
    }

}
/*
window.addEventListener('load', function(){
    upload_file_to_check_virus()
})
function upload_file_to_check_virus(){
    var e = document.getElementById("virus_check_file");
    e.addEventListener('change', function (){
        var selected_file = e.files[0];
        var full_file_name = selected_file.name.toString();

        // Tạo một hidden input để chứa tên file
        var hiddenInput = document.createElement('input');
        hiddenInput.type = 'hidden';
        hiddenInput.name = 'a';  // Tên field mà bạn sẽ sử dụng trong Flask để lấy dữ liệu
        hiddenInput.value = full_file_name;

        // Tìm form để thêm hidden input vào
        var form = document.createElement('form');
        form.method = 'POST';
        form.action = '/ip_upload';

        // Thêm hidden input vào form
        form.appendChild(hiddenInput);

        // Gửi form tự động
        document.body.appendChild(form);  // Thêm form vào body để có thể gửi đi
        form.submit();
    });
}

*/
window.addEventListener('load', function(){
    var fileInput = document.getElementById("virus_check_file");
    var uploadButton = document.getElementById("ioc_button");
    if (uploadButton){
        uploadButton.addEventListener('click', function(){
            upload_file_to_check_virus(fileInput);
        });
    }
});


function upload_file_to_check_virus(fileInput){
    var selected_file = fileInput.files[0];
    if (!selected_file) {
        Swal.fire({
            title: "Chưa chọn file!",
            text: "Hãy chọn file ip cần check!",
            icon: "warning"
        });
        return;
    }

    // Sử dụng FileReader để đọc nội dung file
    var reader = new FileReader();
    reader.onload = function(e) {
        var fileContent = e.target.result;
        var ipArray = fileContent.split(/\r?\n/).filter(Boolean); 

        var ipArrayJSON = JSON.stringify(ipArray);

        var hiddenInput = document.createElement('input');
        hiddenInput.type = 'hidden';
        hiddenInput.name = 'ip_list';  
        hiddenInput.value = ipArrayJSON;

        var form = document.createElement('form');
        form.method = 'POST';
        form.action = '/ip_upload_2';

        // Thêm hidden input vào form
        form.appendChild(hiddenInput);

        // Thêm form vào body và tự động submit
        document.body.appendChild(form);
        form.submit();

        // Xóa form sau khi submit để tránh tạo nhiều form không cần thiết
        document.body.removeChild(form);
    };

    // Đọc file dưới dạng text
    reader.readAsText(selected_file);
}

/*
function upload_file_to_check_virus(fileInput){
    var selected_file = fileInput.files[0];
    if (!selected_file) {
        Swal.fire({
            title: "Chưa chọn file!",
            text: "Hãy chọn file ip cần check!",
            icon: "warning"
        });
        return;
    }

    var reader = new FileReader();
    reader.onload = function(e) {
        var fileContent = e.target.result;
        var ipArray = fileContent.split(/\r?\n/).filter(Boolean); 
        console.log(ipArray);
        sendDataToBackend(ipArray);
    };

    // Đọc file dưới dạng text
    reader.readAsText(selected_file);
}

function sendDataToBackend(ipArray) {
    // Sử dụng fetch để gửi mảng địa chỉ IP qua backend
    fetch('/ip_upload_2', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ip_list: ipArray }), // Gửi dưới dạng JSON
    });
}
*/

/*
function upload_file_to_check_virus(){
    var e = document.getElementById("virus_check_file")
    e.addEventListener('change', function (){
        var selected_file = e.files[0]
        var full_file_name = selected_file.name.toString()
        $.ajax({
            type: 'POST',
            url: '/ip_upload',
            data: {
                a: full_file_name
            },
            success: function(response) {
                console.log("print")
            },
            error: function(error) {
                console.log("error");
            }
        }); 
    })
}

*/

window.addEventListener('load', function(){
    end_button_click()
})

function end_button_click(){
    var e = document.getElementById("end_button")
    if (e){
       e.addEventListener('click', function (){
        $.ajax({
            type: 'POST',
            url: '/end',
            data: {
                interface_name: "a"
            },
            success: function(response) {
                Swal.fire({
                    title: "Kết thúc!",
                    text: "Đã dừng việc giám sát!",
                    icon: "success"
                  });
            },
            error: function(error) {
                console.log("error");
            }
        }); 
    })     
    }
}

window.addEventListener('load', function(){
    start_button_click()
})

function start_button_click(){
    var e = document.getElementById("start_button")
    if(e){
        e.addEventListener('click', function (){
            $.ajax({
                type: 'POST',
                url: '/start',
                data: {
                    interface_name: "a"
                },
                success: function(response) {
                    console.log(response)
                    if (response == '1'){
                        Swal.fire({
                            title: "Bắt đầu!",
                            text: "Bắt đầu hoạt động giám sát!",
                            icon: "success"
                          });
                    }
                    else{
                        Swal.fire({
                            title: "Lỗi!",
                            text: "Hệ thống đang thực hiện giám sát!",
                            icon: "error"
                          });
                    }
    
                        
                },
                error: function(error) {
                    console.log("error");
                }
            }); 
        })
    }
}


window.addEventListener('load', function(){
    sign_in_button_listener_3()
})


function sign_in_button_listener_2() {
    var e = document.getElementById("sign_in_button");
    if (e){
        e.addEventListener('click', function () {
            const email = document.querySelector('input[aria-label="Email"]').value;
            const password = document.querySelector('input[aria-label="Password"]').value;
            if (email === "" || password === "") {
                Swal.fire({
                    title: "Nhập thông tin!",
                    text: "Nhập đầy đủ thông tin đăng nhập!",
                    icon: "warning" 
                });
            } else {
                $.ajax({
                    type: 'POST',
                    url: '/sign_in',
                    data: {
                        email: email,
                        password: password
                    },
                    success: function (response) {
                        if (response == '0'){
                            Swal.fire({
                                title: "Đăng nhập thất bại!",
                                text: "Thông tin đăng nhập không chính xác!",
                                icon: "warning"
                            });
                        } else{
                            window.location.href = '/virus_check'
                        }
    
    
                    },
                    error: function (error) {
                        console.log("error");
                    }
                });
            }
        });
    }
}


function sign_in_button_listener_3(){
    var e = document.getElementById('sign_in_button')
    if (e){
        e.addEventListener('click', function () {
            const email = document.querySelector('input[aria-label="Email"]').value;
            const password = document.querySelector('input[aria-label="Password"]').value;
    
            if (email === "" || password === "") {
                Swal.fire({
                    title: "Nhập thông tin!",
                    text: "Hãy nhập đầy đủ email và mật khẩu",
                    icon: "warning"
                });
                return;
            }
            fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: `email=${email}&password=${password}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    Swal.fire({
                        title: "Thành công!",
                        text: data.message,
                        icon: "success"
                    }).then(() => {
                        window.location.href = "/virus_check";  // Chuyển hướng đến trang được bảo vệ
                    });
                } else {
                    Swal.fire({
                        title: "Lỗi!",
                        text: data.message,
                        icon: "error"
                    });
                }
            })
            .catch(error => console.log('Error:', error));
        });
    }
}


window.addEventListener('load', function(){
    logout_listener()
})

function logout_listener(){
    var e = document.getElementById('logout_button')
    if (e){
        e.addEventListener('click', function () {
        fetch('/logout', {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                Swal.fire({
                    title: "Thành công!",
                    text: data.message,
                    icon: "success"
                }).then(() => {
                    window.location.href = "/";  // Chuyển hướng đến trang được bảo vệ
                });
            } else {
                Swal.fire({
                    title: "Lỗi!",
                    text: "Có lỗi xảy ra khi đăng xuất",
                    icon: "error"
                });
            }
        })
        .catch(error => console.log('Error:', error));
    });
    }

}


window.addEventListener('load', function(){
    update_button()
})


function update_button() {

    var e = document.getElementById("update_button");
    e.addEventListener('click', function () {
        // Lấy nội dung từ textarea
        var textareaContent = document.getElementById('blacklist-textbox-update').value;
        console.log('Nhật')
        console.log(textareaContent)
        // Chuyển nội dung thành mảng, mỗi dòng là một phần tử
        var ipArray = textareaContent.split('\n').map(ip => ip.trim()).filter(ip => ip !== '');
    
        // Kiểm tra nếu textarea trống
        if (ipArray.length === 0) {
            Swal.fire({
            title: "Chưa nhập IP!",
            text: "Hãy nhập danh sách IP cần cập nhật!",
            icon: "warning"
            });
            return;
        }
    
        // Chuyển mảng IP thành JSON string
        var ipArrayJSON = JSON.stringify(ipArray);
    
        // Lấy giá trị và chỉ số của select box
        var selectBox = document.getElementById('color-select');
        var selectedList = selectBox.value;
        var selectedIndex = selectBox.selectedIndex;
    
        // Tạo các input ẩn để chứa dữ liệu
        var listTypeInput = document.createElement('input');
        listTypeInput.type = 'hidden';
        listTypeInput.name = 'listType';
        listTypeInput.value = selectedList;
    
        var listIndexInput = document.createElement('input');
        listIndexInput.type = 'hidden';
        listIndexInput.name = 'listIndex';
        listIndexInput.value = selectedIndex;
    
        var ipListInput = document.createElement('input');
        ipListInput.type = 'hidden';
        ipListInput.name = 'ips';
        ipListInput.value = ipArrayJSON;
    
        // Tạo form và thêm các input ẩn vào
        var form = document.createElement('form');
        form.method = 'POST';
        form.action = '/update_list';
    
        form.appendChild(listTypeInput);
        form.appendChild(listIndexInput);
        form.appendChild(ipListInput);
    
        // Thêm form vào body và tự động submit
        document.body.appendChild(form);
        form.submit();
    
        // Xóa form sau khi submit để tránh tạo nhiều form không cần thiết
        document.body.removeChild(form);
         
    });
    
}