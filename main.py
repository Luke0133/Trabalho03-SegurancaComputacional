from helpers import user_interface as ui

# Trabalho 3 de Segurança Computacional feito por 
# Eduardo Pereira - 231018937 
# Luca Megiorin - 231003390

def main():
    while True:
        choice = ui.main_ui()
        match choice:
            case 1:
                ui.ui_generate_keys()
            case 2:
                ui.ui_sign_verify()
            case _:
                return

if __name__ == "__main__":
    main()


