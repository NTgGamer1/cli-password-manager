from __future__ import annotations

import customtkinter as ctk
from typing import Callable, Optional

import utils.auth as auth
import utils.database as db
import utils.encryption as enc


ctk.set_appearance_mode("dark")

APP_TITLE = "🔐 SecureVault"
DEFAULT_MASTER_PASSWORD = "mysecret"
ACCENT_COLOR = "#4A90D9"
ACCENT_HOVER_COLOR = "#3A78B2"
BACKGROUND_COLOR = "#0F1115"
CARD_COLOR = "#181C23"
PANEL_COLOR = "#131922"
ROW_COLOR = "#171D27"
ROW_SELECTED_COLOR = "#223447"
BORDER_COLOR = "#2A3442"
TEXT_COLOR = "#F5F7FA"
MUTED_TEXT_COLOR = "#94A3B8"
ERROR_COLOR = "#FF6B6B"
SUCCESS_COLOR = "#57C785"


# This function centers a window on the user's screen.
# Inputs:
#     window: The CustomTkinter window we want to move.
#     width: The width we want the window to use.
#     height: The height we want the window to use.
# Outputs:
#     None. The function updates the window geometry in place.
def center_window(window, width: int, height: int) -> None:
    # update_idletasks() asks Tkinter to calculate the newest sizes before we place the window.
    window.update_idletasks()

    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()

    x_position = (screen_width - width) // 2
    y_position = (screen_height - height) // 2

    window.geometry(f"{width}x{height}+{x_position}+{y_position}")


# This function centers a popup dialog relative to its parent window.
# Inputs:
#     child_window: The popup window we just created.
#     parent_window: The main application window that owns the popup.
#     width: The target width for the popup.
#     height: The target height for the popup.
# Outputs:
#     None. The popup is moved so it appears centered over the parent.
def center_child_window(
    child_window: ctk.CTkToplevel, parent_window: ctk.CTk, width: int, height: int
) -> None:
    child_window.update_idletasks()

    parent_x = parent_window.winfo_x()
    parent_y = parent_window.winfo_y()
    parent_width = parent_window.winfo_width()
    parent_height = parent_window.winfo_height()

    x_position = parent_x + (parent_width - width) // 2
    y_position = parent_y + (parent_height - height) // 2

    child_window.geometry(f"{width}x{height}+{x_position}+{y_position}")


# This function updates any inline status label with a success or error message.
# Inputs:
#     label: The label widget that should display feedback to the user.
#     message: The text we want to show.
#     success: True for green success text, False for red error text.
# Outputs:
#     None. The label is reconfigured in place.
def set_status_message(label: ctk.CTkLabel, message: str, success: bool) -> None:
    label.configure(
        text=message,
        text_color=SUCCESS_COLOR if success else ERROR_COLOR,
    )


# This function toggles a password field between hidden and visible text.
# Inputs:
#     entry: The password entry widget the user is typing into.
#     button: The small button that should change its label to match the state.
# Outputs:
#     None. The entry masking and button label are updated in place.
def toggle_password_entry(entry: ctk.CTkEntry, button: ctk.CTkButton) -> None:
    # cget("show") lets us read the current masking character from the entry.
    is_hidden = entry.cget("show") == "*"

    entry.configure(show="" if is_hidden else "*")
    button.configure(text="👁 Hide" if is_hidden else "👁 Show")


# This function turns a real password into a masked string for safer display in the table.
# Inputs:
#     password_text: The decrypted password string.
# Outputs:
#     str: A bullet-masked version so the password is not visible by default.
def mask_password(password_text: str) -> str:
    # We keep the mask length in a small readable range so very long passwords do not stretch the row.
    mask_length = max(8, min(len(password_text), 18))
    return "•" * mask_length


# This function formats the raw SQLite timestamp into a shorter display-friendly version.
# Inputs:
#     created_at: The timestamp string stored by SQLite.
# Outputs:
#     str: A simplified timestamp string for the GUI table.
def format_created_at(created_at: str) -> str:
    if not created_at:
        return "-"

    # SQLite usually returns "YYYY-MM-DD HH:MM:SS", so trimming seconds keeps the table cleaner.
    return created_at[:16]


class PasswordDialog(ctk.CTkToplevel):
    # This constructor builds the add/edit password popup window.
    # Inputs:
    #     parent: The main SecureVault window that owns this dialog.
    #     session_key: The active encryption key for the logged-in user.
    #     refresh_callback: A function we call after saving so the main table refreshes.
    #     mode: Either "add" or "edit" so the dialog knows which database action to run.
    #     entry_data: Optional existing password data used to pre-fill the edit form.
    # Outputs:
    #     None. A ready-to-use modal popup is created.
    def __init__(
        self,
        parent: "SecureVaultApp",
        session_key: bytes,
        refresh_callback: Callable[[str, bool], None],
        mode: str,
        entry_data: Optional[dict] = None,
    ) -> None:
        super().__init__(parent)

        self.parent = parent
        self.session_key = session_key
        self.refresh_callback = refresh_callback
        self.mode = mode
        self.entry_data = entry_data or {}

        self.title(APP_TITLE)
        self.configure(fg_color=BACKGROUND_COLOR)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.build_dialog()
        center_child_window(self, parent, 520, 380)

    # This function draws the add/edit password form inside the popup.
    # Inputs:
    #     None. It uses the dialog state stored on self.
    # Outputs:
    #     None. The popup widgets are created and arranged on screen.
    def build_dialog(self) -> None:
        card = ctk.CTkFrame(
            self,
            corner_radius=18,
            fg_color=CARD_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        card.pack(fill="both", expand=True, padx=18, pady=18)

        ctk.CTkLabel(
            card,
            text=APP_TITLE,
            font=self.parent.heading_font,
            text_color=TEXT_COLOR,
        ).pack(pady=(20, 6))

        ctk.CTkLabel(
            card,
            text="Add Password" if self.mode == "add" else "Edit Password",
            font=self.parent.body_font,
            text_color=MUTED_TEXT_COLOR,
        ).pack(pady=(0, 18))

        form = ctk.CTkFrame(card, fg_color="transparent")
        form.pack(fill="x", padx=24)
        form.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            form,
            text="Service",
            font=self.parent.body_font,
            anchor="w",
            text_color=TEXT_COLOR,
        ).grid(row=0, column=0, sticky="ew", pady=(0, 6))

        self.service_entry = ctk.CTkEntry(
            form,
            height=40,
            corner_radius=12,
            font=self.parent.body_font,
            border_color=BORDER_COLOR,
        )
        self.service_entry.grid(row=1, column=0, sticky="ew", pady=(0, 14))

        ctk.CTkLabel(
            form,
            text="Username",
            font=self.parent.body_font,
            anchor="w",
            text_color=TEXT_COLOR,
        ).grid(row=2, column=0, sticky="ew", pady=(0, 6))

        self.username_entry = ctk.CTkEntry(
            form,
            height=40,
            corner_radius=12,
            font=self.parent.body_font,
            border_color=BORDER_COLOR,
        )
        self.username_entry.grid(row=3, column=0, sticky="ew", pady=(0, 14))

        ctk.CTkLabel(
            form,
            text="Password",
            font=self.parent.body_font,
            anchor="w",
            text_color=TEXT_COLOR,
        ).grid(row=4, column=0, sticky="ew", pady=(0, 6))

        password_row = ctk.CTkFrame(form, fg_color="transparent")
        password_row.grid(row=5, column=0, sticky="ew")
        password_row.grid_columnconfigure(0, weight=1)

        self.password_entry = ctk.CTkEntry(
            password_row,
            height=40,
            corner_radius=12,
            font=self.parent.body_font,
            border_color=BORDER_COLOR,
            show="*",
        )
        self.password_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        self.password_toggle_button = ctk.CTkButton(
            password_row,
            text="👁 Show",
            width=90,
            height=40,
            corner_radius=12,
            font=self.parent.body_font,
            fg_color=PANEL_COLOR,
            hover_color=ROW_SELECTED_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
            command=self.toggle_password_visibility,
        )
        self.password_toggle_button.grid(row=0, column=1)

        self.status_label = ctk.CTkLabel(
            card,
            text="",
            font=self.parent.body_font,
            text_color=ERROR_COLOR,
            wraplength=420,
            justify="left",
        )
        self.status_label.pack(fill="x", padx=24, pady=(18, 0))

        ctk.CTkButton(
            card,
            text="Save",
            height=42,
            corner_radius=12,
            font=self.parent.body_font,
            fg_color=ACCENT_COLOR,
            hover_color=ACCENT_HOVER_COLOR,
            command=self.save_password,
        ).pack(fill="x", padx=24, pady=(16, 24))

        # When editing, we pre-fill the form so the user can adjust only what they want to change.
        if self.entry_data:
            self.service_entry.insert(0, self.entry_data.get("service", ""))
            self.username_entry.insert(0, self.entry_data.get("username", ""))
            self.password_entry.insert(0, self.entry_data.get("password", ""))

    # This function flips the dialog password field between hidden and visible text.
    # Inputs:
    #     None. It uses the dialog's saved entry/button widgets.
    # Outputs:
    #     None. The password field display is updated.
    def toggle_password_visibility(self) -> None:
        toggle_password_entry(self.password_entry, self.password_toggle_button)

    # This function validates the form, encrypts the password, and saves it to the database.
    # Inputs:
    #     None. It reads the current form field values from the dialog widgets.
    # Outputs:
    #     None. On success, the database is updated and the dialog closes.
    def save_password(self) -> None:
        service = self.service_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not service or not username or not password:
            set_status_message(
                self.status_label,
                "Please fill in Service, Username, and Password before saving.",
                False,
            )
            return

        try:
            encrypted_password = enc.encrypt_password(self.session_key, password)

            if self.mode == "add":
                db.add_password(service, username, encrypted_password)
                self.refresh_callback(f"Saved password for {service}.", True)
            else:
                db.update_password(
                    self.entry_data["id"],
                    service,
                    username,
                    encrypted_password,
                )
                self.refresh_callback(f"Updated password for {service}.", True)

            self.destroy()
        except Exception as error:
            set_status_message(
                self.status_label,
                f"Could not save this password entry: {error}",
                False,
            )


class ChangeMasterPasswordDialog(ctk.CTkToplevel):
    # This constructor builds the master-password change popup.
    # Inputs:
    #     parent: The main SecureVault window.
    #     change_callback: A function that performs the actual verification and re-encryption work.
    # Outputs:
    #     None. The modal dialog is created and shown.
    def __init__(
        self,
        parent: "SecureVaultApp",
        change_callback: Callable[[str, str, str], tuple[bool, str]],
    ) -> None:
        super().__init__(parent)

        self.parent = parent
        self.change_callback = change_callback

        self.title(APP_TITLE)
        self.configure(fg_color=BACKGROUND_COLOR)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.build_dialog()
        center_child_window(self, parent, 560, 470)

    # This function draws the full master-password form.
    # Inputs:
    #     None. It uses saved dialog state on self.
    # Outputs:
    #     None. The dialog widgets are added to the popup.
    def build_dialog(self) -> None:
        card = ctk.CTkFrame(
            self,
            corner_radius=18,
            fg_color=CARD_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        card.pack(fill="both", expand=True, padx=18, pady=18)

        ctk.CTkLabel(
            card,
            text=APP_TITLE,
            font=self.parent.heading_font,
            text_color=TEXT_COLOR,
        ).pack(pady=(20, 6))

        ctk.CTkLabel(
            card,
            text="Change Master Password",
            font=self.parent.body_font,
            text_color=MUTED_TEXT_COLOR,
        ).pack(pady=(0, 10))

        ctk.CTkLabel(
            card,
            text="Your whole vault will be decrypted with the current key and re-encrypted with the new one.",
            font=self.parent.body_font,
            text_color=MUTED_TEXT_COLOR,
            wraplength=460,
            justify="left",
        ).pack(padx=24, pady=(0, 18))

        form = ctk.CTkFrame(card, fg_color="transparent")
        form.pack(fill="x", padx=24)
        form.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            form,
            text="Current Password",
            font=self.parent.body_font,
            anchor="w",
            text_color=TEXT_COLOR,
        ).grid(row=0, column=0, sticky="ew", pady=(0, 6))

        current_row = ctk.CTkFrame(form, fg_color="transparent")
        current_row.grid(row=1, column=0, sticky="ew", pady=(0, 14))
        current_row.grid_columnconfigure(0, weight=1)

        self.current_password_entry = ctk.CTkEntry(
            current_row,
            height=40,
            corner_radius=12,
            font=self.parent.body_font,
            border_color=BORDER_COLOR,
            show="*",
        )
        self.current_password_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        self.current_toggle_button = ctk.CTkButton(
            current_row,
            text="👁 Show",
            width=90,
            height=40,
            corner_radius=12,
            font=self.parent.body_font,
            fg_color=PANEL_COLOR,
            hover_color=ROW_SELECTED_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
            command=lambda: toggle_password_entry(
                self.current_password_entry, self.current_toggle_button
            ),
        )
        self.current_toggle_button.grid(row=0, column=1)

        ctk.CTkLabel(
            form,
            text="New Password",
            font=self.parent.body_font,
            anchor="w",
            text_color=TEXT_COLOR,
        ).grid(row=2, column=0, sticky="ew", pady=(0, 6))

        new_row = ctk.CTkFrame(form, fg_color="transparent")
        new_row.grid(row=3, column=0, sticky="ew", pady=(0, 14))
        new_row.grid_columnconfigure(0, weight=1)

        self.new_password_entry = ctk.CTkEntry(
            new_row,
            height=40,
            corner_radius=12,
            font=self.parent.body_font,
            border_color=BORDER_COLOR,
            show="*",
        )
        self.new_password_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        self.new_toggle_button = ctk.CTkButton(
            new_row,
            text="👁 Show",
            width=90,
            height=40,
            corner_radius=12,
            font=self.parent.body_font,
            fg_color=PANEL_COLOR,
            hover_color=ROW_SELECTED_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
            command=lambda: toggle_password_entry(
                self.new_password_entry, self.new_toggle_button
            ),
        )
        self.new_toggle_button.grid(row=0, column=1)

        ctk.CTkLabel(
            form,
            text="Confirm New Password",
            font=self.parent.body_font,
            anchor="w",
            text_color=TEXT_COLOR,
        ).grid(row=4, column=0, sticky="ew", pady=(0, 6))

        confirm_row = ctk.CTkFrame(form, fg_color="transparent")
        confirm_row.grid(row=5, column=0, sticky="ew")
        confirm_row.grid_columnconfigure(0, weight=1)

        self.confirm_password_entry = ctk.CTkEntry(
            confirm_row,
            height=40,
            corner_radius=12,
            font=self.parent.body_font,
            border_color=BORDER_COLOR,
            show="*",
        )
        self.confirm_password_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        self.confirm_toggle_button = ctk.CTkButton(
            confirm_row,
            text="👁 Show",
            width=90,
            height=40,
            corner_radius=12,
            font=self.parent.body_font,
            fg_color=PANEL_COLOR,
            hover_color=ROW_SELECTED_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
            command=lambda: toggle_password_entry(
                self.confirm_password_entry, self.confirm_toggle_button
            ),
        )
        self.confirm_toggle_button.grid(row=0, column=1)

        self.status_label = ctk.CTkLabel(
            card,
            text="",
            font=self.parent.body_font,
            text_color=ERROR_COLOR,
            wraplength=460,
            justify="left",
        )
        self.status_label.pack(fill="x", padx=24, pady=(18, 0))

        ctk.CTkButton(
            card,
            text="Update Master Password",
            height=42,
            corner_radius=12,
            font=self.parent.body_font,
            fg_color=ACCENT_COLOR,
            hover_color=ACCENT_HOVER_COLOR,
            command=self.submit_change,
        ).pack(fill="x", padx=24, pady=(16, 24))

    # This function asks the main app to process the password change request.
    # Inputs:
    #     None. It reads the current form values from this popup.
    # Outputs:
    #     None. On success the popup closes, otherwise an inline error is shown.
    def submit_change(self) -> None:
        current_password = self.current_password_entry.get().strip()
        new_password = self.new_password_entry.get().strip()
        confirm_password = self.confirm_password_entry.get().strip()

        success, message = self.change_callback(
            current_password, new_password, confirm_password
        )

        set_status_message(self.status_label, message, success)

        if success:
            # A short delay gives the user time to read the green success message before the popup closes.
            self.after(700, self.destroy)


class DeleteConfirmationDialog(ctk.CTkToplevel):
    # This constructor builds a small confirmation popup before deleting an entry.
    # Inputs:
    #     parent: The main SecureVault window.
    #     entry_data: The selected password row so we can show the user what will be deleted.
    #     confirm_callback: A function that runs the actual database delete.
    # Outputs:
    #     None. The modal confirmation dialog is created.
    def __init__(
        self,
        parent: "SecureVaultApp",
        entry_data: dict,
        confirm_callback: Callable[[int], tuple[bool, str]],
    ) -> None:
        super().__init__(parent)

        self.parent = parent
        self.entry_data = entry_data
        self.confirm_callback = confirm_callback

        self.title(APP_TITLE)
        self.configure(fg_color=BACKGROUND_COLOR)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.build_dialog()
        center_child_window(self, parent, 460, 280)

    # This function draws the delete confirmation UI.
    # Inputs:
    #     None. It uses the selected entry already stored on self.
    # Outputs:
    #     None. The confirmation widgets are added to the popup.
    def build_dialog(self) -> None:
        card = ctk.CTkFrame(
            self,
            corner_radius=18,
            fg_color=CARD_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        card.pack(fill="both", expand=True, padx=18, pady=18)

        ctk.CTkLabel(
            card,
            text=APP_TITLE,
            font=self.parent.heading_font,
            text_color=TEXT_COLOR,
        ).pack(pady=(20, 8))

        ctk.CTkLabel(
            card,
            text=(
                f"Delete '{self.entry_data['service']}' for "
                f"'{self.entry_data['username']}'?"
            ),
            font=self.parent.body_font,
            text_color=TEXT_COLOR,
            wraplength=360,
            justify="center",
        ).pack(padx=24, pady=(0, 10))

        ctk.CTkLabel(
            card,
            text="This action removes the saved entry from your local vault.",
            font=self.parent.body_font,
            text_color=MUTED_TEXT_COLOR,
            wraplength=360,
            justify="center",
        ).pack(padx=24)

        self.status_label = ctk.CTkLabel(
            card,
            text="",
            font=self.parent.body_font,
            text_color=ERROR_COLOR,
        )
        self.status_label.pack(pady=(14, 0))

        button_row = ctk.CTkFrame(card, fg_color="transparent")
        button_row.pack(fill="x", padx=24, pady=(18, 24))
        button_row.grid_columnconfigure(0, weight=1)
        button_row.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(
            button_row,
            text="Cancel",
            height=40,
            corner_radius=12,
            font=self.parent.body_font,
            fg_color=PANEL_COLOR,
            hover_color=ROW_SELECTED_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
            command=self.destroy,
        ).grid(row=0, column=0, sticky="ew", padx=(0, 8))

        ctk.CTkButton(
            button_row,
            text="Delete",
            height=40,
            corner_radius=12,
            font=self.parent.body_font,
            fg_color="#C44545",
            hover_color="#A73838",
            command=self.confirm_delete,
        ).grid(row=0, column=1, sticky="ew", padx=(8, 0))

    # This function runs the delete callback and closes the popup if it succeeds.
    # Inputs:
    #     None. It uses the selected row already stored on the dialog.
    # Outputs:
    #     None. The database row may be deleted and the popup may close.
    def confirm_delete(self) -> None:
        success, message = self.confirm_callback(self.entry_data["id"])
        set_status_message(self.status_label, message, success)

        if success:
            self.after(400, self.destroy)


class SecureVaultApp(ctk.CTk):
    # This constructor prepares the main GUI window and decides which screen to show first.
    # Inputs:
    #     None. Everything needed is loaded from the local project modules.
    # Outputs:
    #     None. A fully configured application window is created.
    def __init__(self) -> None:
        super().__init__()

        self.body_font = ctk.CTkFont(size=13)
        self.heading_font = ctk.CTkFont(size=20, weight="bold")

        self.session_key: Optional[bytes] = None
        self.login_attempts = 0
        self.selected_password_id: Optional[int] = None
        self.password_visibility: dict[int, bool] = {}
        self.password_cache: dict[int, str] = {}
        self.password_rows: dict[int, tuple] = {}
        self.row_frames: dict[int, ctk.CTkFrame] = {}

        self.configure_window()
        self.bootstrap_application()

    # This function applies the basic root-window styling and sizing rules.
    # Inputs:
    #     None. It uses the visual constants defined at the top of the file.
    # Outputs:
    #     None. The root window is styled and centered.
    def configure_window(self) -> None:
        self.title(APP_TITLE)
        self.configure(fg_color=BACKGROUND_COLOR)
        self.minsize(900, 600)
        center_window(self, 1000, 650)

    # This function initializes the database and chooses the correct first screen.
    # Inputs:
    #     None. It reads the current setup state from the auth/database layer.
    # Outputs:
    #     None. The login screen or first-run setup screen is displayed.
    def bootstrap_application(self) -> None:
        db.init_db()

        if not auth.check_if_setup():
            self.ensure_default_master_password()
            self.show_setup_screen()
        else:
            self.show_login_screen()

    # This function preserves the CLI app's first-run behavior by creating the default password.
    # Inputs:
    #     None. The default password value comes from the constant at the top of the file.
    # Outputs:
    #     None. The default master password hash is stored in the database.
    def ensure_default_master_password(self) -> None:
        auth.hash_and_save_master_password(DEFAULT_MASTER_PASSWORD)

    # This function removes the current screen so a new one can be drawn cleanly.
    # Inputs:
    #     None. It simply looks at the root window's existing child widgets.
    # Outputs:
    #     None. Existing widgets are destroyed.
    def clear_screen(self) -> None:
        for widget in self.winfo_children():
            widget.destroy()

    # This function builds the centered login screen.
    # Inputs:
    #     message: Optional text to show as feedback when the screen opens.
    #     success: True for green feedback, False for red feedback.
    # Outputs:
    #     None. The login UI is drawn on the root window.
    def show_login_screen(self, message: str = "", success: bool = False) -> None:
        self.clear_screen()
        self.login_attempts = 0

        wrapper = ctk.CTkFrame(self, fg_color="transparent")
        wrapper.pack(fill="both", expand=True, padx=24, pady=24)
        wrapper.grid_rowconfigure(0, weight=1)
        wrapper.grid_columnconfigure(0, weight=1)

        card = ctk.CTkFrame(
            wrapper,
            width=420,
            corner_radius=20,
            fg_color=CARD_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        card.grid(row=0, column=0)
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card,
            text=APP_TITLE,
            font=self.heading_font,
            text_color=TEXT_COLOR,
        ).grid(row=0, column=0, padx=32, pady=(28, 8))

        ctk.CTkLabel(
            card,
            text="Enter your master password to unlock the vault.",
            font=self.body_font,
            text_color=MUTED_TEXT_COLOR,
        ).grid(row=1, column=0, padx=32, pady=(0, 20))

        ctk.CTkLabel(
            card,
            text="Master Password",
            font=self.body_font,
            text_color=TEXT_COLOR,
            anchor="w",
        ).grid(row=2, column=0, sticky="ew", padx=32, pady=(0, 6))

        password_row = ctk.CTkFrame(card, fg_color="transparent")
        password_row.grid(row=3, column=0, sticky="ew", padx=32)
        password_row.grid_columnconfigure(0, weight=1)

        self.login_password_entry = ctk.CTkEntry(
            password_row,
            height=42,
            corner_radius=12,
            font=self.body_font,
            border_color=BORDER_COLOR,
            show="*",
        )
        self.login_password_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.login_password_entry.bind("<Return>", lambda _event: self.attempt_login())

        self.login_toggle_button = ctk.CTkButton(
            password_row,
            text="👁 Show",
            width=95,
            height=42,
            corner_radius=12,
            font=self.body_font,
            fg_color=PANEL_COLOR,
            hover_color=ROW_SELECTED_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
            command=lambda: toggle_password_entry(
                self.login_password_entry, self.login_toggle_button
            ),
        )
        self.login_toggle_button.grid(row=0, column=1)

        self.login_status_label = ctk.CTkLabel(
            card,
            text="",
            font=self.body_font,
            text_color=ERROR_COLOR,
            wraplength=340,
            justify="left",
        )
        self.login_status_label.grid(row=4, column=0, sticky="ew", padx=32, pady=(18, 0))

        self.login_button = ctk.CTkButton(
            card,
            text="Login",
            height=42,
            corner_radius=12,
            font=self.body_font,
            fg_color=ACCENT_COLOR,
            hover_color=ACCENT_HOVER_COLOR,
            command=self.attempt_login,
        )
        self.login_button.grid(row=5, column=0, sticky="ew", padx=32, pady=(16, 28))

        if message:
            set_status_message(self.login_status_label, message, success)

        # focus() places the typing cursor into the password field so the user can start immediately.
        self.login_password_entry.focus()

    # This function validates the login form and enforces the CLI-style three-attempt limit.
    # Inputs:
    #     None. It reads the entered password from the login field.
    # Outputs:
    #     None. The app either unlocks the vault or shows an inline error/lockout message.
    def attempt_login(self) -> None:
        password = self.login_password_entry.get().strip()

        if not password:
            set_status_message(
                self.login_status_label,
                "Please enter your master password before logging in.",
                False,
            )
            return

        if auth.verify_master_password(password):
            self.session_key = enc.derive_key_from_password(password)
            self.show_vault_screen("Access granted. Welcome back to your vault.", True)
            return

        self.login_attempts += 1
        remaining_attempts = 3 - self.login_attempts

        if remaining_attempts <= 0:
            set_status_message(
                self.login_status_label,
                "Too many failed attempts. The application will close to match the CLI lockout.",
                False,
            )
            self.lock_login_screen()
            self.after(1800, self.destroy)
            return

        set_status_message(
            self.login_status_label,
            f"Access denied. {remaining_attempts} attempt(s) remaining.",
            False,
        )
        self.login_password_entry.delete(0, "end")

    # This function disables the login controls after the user runs out of attempts.
    # Inputs:
    #     None. It uses the already-created login widgets.
    # Outputs:
    #     None. The widgets are disabled in place.
    def lock_login_screen(self) -> None:
        self.login_password_entry.configure(state="disabled")
        self.login_toggle_button.configure(state="disabled")
        self.login_button.configure(state="disabled")

    # This function builds the first-run setup screen.
    # Inputs:
    #     message: Optional status text shown on the setup card.
    #     success: True for green text, False for red text.
    # Outputs:
    #     None. The setup UI is drawn on screen.
    def show_setup_screen(self, message: str = "", success: bool = False) -> None:
        self.clear_screen()

        wrapper = ctk.CTkFrame(self, fg_color="transparent")
        wrapper.pack(fill="both", expand=True, padx=24, pady=24)
        wrapper.grid_rowconfigure(0, weight=1)
        wrapper.grid_columnconfigure(0, weight=1)

        card = ctk.CTkFrame(
            wrapper,
            width=520,
            corner_radius=20,
            fg_color=CARD_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        card.grid(row=0, column=0)
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card,
            text=APP_TITLE,
            font=self.heading_font,
            text_color=TEXT_COLOR,
        ).grid(row=0, column=0, padx=36, pady=(28, 8))

        ctk.CTkLabel(
            card,
            text="First-time setup",
            font=self.body_font,
            text_color=MUTED_TEXT_COLOR,
        ).grid(row=1, column=0, padx=36, pady=(0, 8))

        ctk.CTkLabel(
            card,
            text=(
                "The CLI version creates a default master password of 'mysecret' on first run. "
                "This GUI keeps that same backend behavior, but lets you replace it right away."
            ),
            font=self.body_font,
            text_color=MUTED_TEXT_COLOR,
            wraplength=420,
            justify="left",
        ).grid(row=2, column=0, sticky="ew", padx=36, pady=(0, 20))

        ctk.CTkLabel(
            card,
            text="New Master Password",
            font=self.body_font,
            text_color=TEXT_COLOR,
            anchor="w",
        ).grid(row=3, column=0, sticky="ew", padx=36, pady=(0, 6))

        new_row = ctk.CTkFrame(card, fg_color="transparent")
        new_row.grid(row=4, column=0, sticky="ew", padx=36)
        new_row.grid_columnconfigure(0, weight=1)

        self.setup_new_password_entry = ctk.CTkEntry(
            new_row,
            height=42,
            corner_radius=12,
            font=self.body_font,
            border_color=BORDER_COLOR,
            show="*",
        )
        self.setup_new_password_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        self.setup_new_toggle_button = ctk.CTkButton(
            new_row,
            text="👁 Show",
            width=95,
            height=42,
            corner_radius=12,
            font=self.body_font,
            fg_color=PANEL_COLOR,
            hover_color=ROW_SELECTED_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
            command=lambda: toggle_password_entry(
                self.setup_new_password_entry, self.setup_new_toggle_button
            ),
        )
        self.setup_new_toggle_button.grid(row=0, column=1)

        ctk.CTkLabel(
            card,
            text="Confirm New Password",
            font=self.body_font,
            text_color=TEXT_COLOR,
            anchor="w",
        ).grid(row=5, column=0, sticky="ew", padx=36, pady=(16, 6))

        confirm_row = ctk.CTkFrame(card, fg_color="transparent")
        confirm_row.grid(row=6, column=0, sticky="ew", padx=36)
        confirm_row.grid_columnconfigure(0, weight=1)

        self.setup_confirm_password_entry = ctk.CTkEntry(
            confirm_row,
            height=42,
            corner_radius=12,
            font=self.body_font,
            border_color=BORDER_COLOR,
            show="*",
        )
        self.setup_confirm_password_entry.grid(
            row=0, column=0, sticky="ew", padx=(0, 10)
        )

        self.setup_confirm_toggle_button = ctk.CTkButton(
            confirm_row,
            text="👁 Show",
            width=95,
            height=42,
            corner_radius=12,
            font=self.body_font,
            fg_color=PANEL_COLOR,
            hover_color=ROW_SELECTED_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
            command=lambda: toggle_password_entry(
                self.setup_confirm_password_entry, self.setup_confirm_toggle_button
            ),
        )
        self.setup_confirm_toggle_button.grid(row=0, column=1)

        self.setup_status_label = ctk.CTkLabel(
            card,
            text="",
            font=self.body_font,
            text_color=ERROR_COLOR,
            wraplength=420,
            justify="left",
        )
        self.setup_status_label.grid(row=7, column=0, sticky="ew", padx=36, pady=(18, 0))

        ctk.CTkButton(
            card,
            text="Finish Setup",
            height=42,
            corner_radius=12,
            font=self.body_font,
            fg_color=ACCENT_COLOR,
            hover_color=ACCENT_HOVER_COLOR,
            command=self.complete_initial_setup,
        ).grid(row=8, column=0, sticky="ew", padx=36, pady=(16, 28))

        if message:
            set_status_message(self.setup_status_label, message, success)

        self.setup_new_password_entry.focus()

    # This function finishes the first-run setup by replacing the default password with the new one.
    # Inputs:
    #     None. It reads the two password fields from the setup card.
    # Outputs:
    #     None. On success the user is logged in and taken to the vault screen.
    def complete_initial_setup(self) -> None:
        new_password = self.setup_new_password_entry.get().strip()
        confirm_password = self.setup_confirm_password_entry.get().strip()

        if not new_password or not confirm_password:
            set_status_message(
                self.setup_status_label,
                "Please enter and confirm your new master password.",
                False,
            )
            return

        if new_password != confirm_password:
            set_status_message(
                self.setup_status_label,
                "The two new password fields do not match.",
                False,
            )
            return

        if new_password == DEFAULT_MASTER_PASSWORD:
            set_status_message(
                self.setup_status_label,
                "Choose something stronger than the default password 'mysecret'.",
                False,
            )
            return

        old_key = enc.derive_key_from_password(DEFAULT_MASTER_PASSWORD)
        new_key = enc.derive_key_from_password(new_password)

        success, message = self.reencrypt_vault(old_key, new_key)
        if not success:
            set_status_message(self.setup_status_label, message, False)
            return

        auth.hash_and_save_master_password(new_password)
        self.session_key = new_key
        self.show_vault_screen("Setup complete. Your vault is now protected by the new password.", True)

    # This function builds the main vault screen with action buttons and a scrollable password list.
    # Inputs:
    #     message: Optional feedback text to show at the top of the screen.
    #     success: True for green feedback, False for red feedback.
    # Outputs:
    #     None. The main application workspace is drawn.
    def show_vault_screen(self, message: str = "", success: bool = True) -> None:
        self.clear_screen()

        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=24, pady=24)
        container.grid_rowconfigure(4, weight=1)
        container.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            container,
            text=APP_TITLE,
            font=self.heading_font,
            text_color=TEXT_COLOR,
        ).grid(row=0, column=0, sticky="w", pady=(0, 10))

        button_bar = ctk.CTkFrame(
            container,
            corner_radius=18,
            fg_color=CARD_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        button_bar.grid(row=1, column=0, sticky="ew")
        for column_index in range(5):
            button_bar.grid_columnconfigure(column_index, weight=1)

        ctk.CTkButton(
            button_bar,
            text="Add",
            height=40,
            corner_radius=12,
            font=self.body_font,
            fg_color=ACCENT_COLOR,
            hover_color=ACCENT_HOVER_COLOR,
            command=self.open_add_dialog,
        ).grid(row=0, column=0, sticky="ew", padx=12, pady=12)

        self.edit_button = ctk.CTkButton(
            button_bar,
            text="Edit",
            height=40,
            corner_radius=12,
            font=self.body_font,
            fg_color=PANEL_COLOR,
            hover_color=ROW_SELECTED_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
            command=self.open_edit_dialog,
        )
        self.edit_button.grid(row=0, column=1, sticky="ew", padx=12, pady=12)

        self.delete_button = ctk.CTkButton(
            button_bar,
            text="Delete",
            height=40,
            corner_radius=12,
            font=self.body_font,
            fg_color=PANEL_COLOR,
            hover_color=ROW_SELECTED_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
            command=self.open_delete_dialog,
        )
        self.delete_button.grid(row=0, column=2, sticky="ew", padx=12, pady=12)

        ctk.CTkButton(
            button_bar,
            text="Change Master Password",
            height=40,
            corner_radius=12,
            font=self.body_font,
            fg_color=PANEL_COLOR,
            hover_color=ROW_SELECTED_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
            command=self.open_change_master_password_dialog,
        ).grid(row=0, column=3, sticky="ew", padx=12, pady=12)

        ctk.CTkButton(
            button_bar,
            text="Logout",
            height=40,
            corner_radius=12,
            font=self.body_font,
            fg_color=PANEL_COLOR,
            hover_color=ROW_SELECTED_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
            command=self.logout,
        ).grid(row=0, column=4, sticky="ew", padx=12, pady=12)

        ctk.CTkLabel(
            container,
            text="Click a row to select it for Edit or Delete. Passwords stay hidden until you reveal them.",
            font=self.body_font,
            text_color=MUTED_TEXT_COLOR,
        ).grid(row=2, column=0, sticky="w", pady=(12, 8))

        self.main_status_label = ctk.CTkLabel(
            container,
            text="",
            font=self.body_font,
            text_color=SUCCESS_COLOR,
            anchor="w",
            justify="left",
        )
        self.main_status_label.grid(row=3, column=0, sticky="ew", pady=(0, 12))

        table_card = ctk.CTkFrame(
            container,
            corner_radius=18,
            fg_color=CARD_COLOR,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        table_card.grid(row=4, column=0, sticky="nsew")
        table_card.grid_rowconfigure(1, weight=1)
        table_card.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(table_card, fg_color=PANEL_COLOR, corner_radius=14)
        header.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 8))
        self.configure_table_columns(header)

        header_labels = ["ID", "Service", "Username", "Password", "Created At"]
        for column_index, text in enumerate(header_labels):
            ctk.CTkLabel(
                header,
                text=text,
                font=self.body_font,
                text_color=TEXT_COLOR,
                anchor="w",
            ).grid(row=0, column=column_index, sticky="ew", padx=12, pady=12)

        self.table_body = ctk.CTkScrollableFrame(
            table_card,
            fg_color="transparent",
            corner_radius=12,
        )
        self.table_body.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))
        self.table_body.grid_columnconfigure(0, weight=1)

        self.refresh_vault_rows()

        if message:
            set_status_message(self.main_status_label, message, success)

    # This function applies the same column sizing to the header and each table row.
    # Inputs:
    #     frame: The frame whose grid columns should be configured.
    # Outputs:
    #     None. The frame's grid weights are updated.
    def configure_table_columns(self, frame: ctk.CTkFrame) -> None:
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=3)
        frame.grid_columnconfigure(2, weight=3)
        frame.grid_columnconfigure(3, weight=4)
        frame.grid_columnconfigure(4, weight=2)

    # This function reloads every saved password row from the database and redraws the scrollable list.
    # Inputs:
    #     None. It uses the active session key and the current database contents.
    # Outputs:
    #     None. The visible table rows are rebuilt.
    def refresh_vault_rows(self) -> None:
        for widget in self.table_body.winfo_children():
            widget.destroy()

        self.password_cache.clear()
        self.password_rows.clear()
        self.row_frames.clear()

        rows = db.get_all_passwords()

        if not rows:
            self.selected_password_id = None
            self.update_action_button_states()

            ctk.CTkLabel(
                self.table_body,
                text="Your vault is empty. Click Add to save your first password.",
                font=self.body_font,
                text_color=MUTED_TEXT_COLOR,
            ).grid(row=0, column=0, sticky="w", padx=12, pady=16)
            return

        for row_index, row in enumerate(rows):
            password_id, service, username, encrypted_password, created_at = row

            try:
                decrypted_password = enc.decrypt_password(self.session_key, encrypted_password)
            except Exception:
                decrypted_password = "[DECRYPTION FAILED]"

            self.password_cache[password_id] = decrypted_password
            self.password_rows[password_id] = row
            self.password_visibility.setdefault(password_id, False)

            row_frame = ctk.CTkFrame(
                self.table_body,
                corner_radius=14,
                fg_color=ROW_SELECTED_COLOR
                if password_id == self.selected_password_id
                else ROW_COLOR,
                border_width=1,
                border_color=ACCENT_COLOR
                if password_id == self.selected_password_id
                else BORDER_COLOR,
            )
            row_frame.grid(row=row_index, column=0, sticky="ew", pady=(0, 8))
            self.configure_table_columns(row_frame)

            self.row_frames[password_id] = row_frame

            id_label = ctk.CTkLabel(
                row_frame,
                text=str(password_id),
                font=self.body_font,
                text_color=TEXT_COLOR,
                anchor="w",
            )
            id_label.grid(row=0, column=0, sticky="ew", padx=12, pady=12)

            service_label = ctk.CTkLabel(
                row_frame,
                text=service,
                font=self.body_font,
                text_color=TEXT_COLOR,
                anchor="w",
            )
            service_label.grid(row=0, column=1, sticky="ew", padx=12, pady=12)

            username_label = ctk.CTkLabel(
                row_frame,
                text=username,
                font=self.body_font,
                text_color=TEXT_COLOR,
                anchor="w",
            )
            username_label.grid(row=0, column=2, sticky="ew", padx=12, pady=12)

            password_cell = ctk.CTkFrame(row_frame, fg_color="transparent")
            password_cell.grid(row=0, column=3, sticky="ew", padx=12, pady=12)
            password_cell.grid_columnconfigure(0, weight=1)

            password_value_label = ctk.CTkLabel(
                password_cell,
                text=decrypted_password
                if self.password_visibility[password_id]
                else mask_password(decrypted_password),
                font=self.body_font,
                text_color=TEXT_COLOR,
                anchor="w",
            )
            password_value_label.grid(row=0, column=0, sticky="ew", padx=(0, 10))

            ctk.CTkButton(
                password_cell,
                text="👁 Hide" if self.password_visibility[password_id] else "👁 Show",
                width=90,
                height=34,
                corner_radius=10,
                font=self.body_font,
                fg_color=PANEL_COLOR,
                hover_color=ROW_SELECTED_COLOR,
                border_width=1,
                border_color=BORDER_COLOR,
                command=lambda current_id=password_id: self.toggle_row_password_visibility(
                    current_id
                ),
            ).grid(row=0, column=1)

            created_at_label = ctk.CTkLabel(
                row_frame,
                text=format_created_at(created_at),
                font=self.body_font,
                text_color=MUTED_TEXT_COLOR,
                anchor="w",
            )
            created_at_label.grid(row=0, column=4, sticky="ew", padx=12, pady=12)

            self.bind_row_selection(
                password_id,
                row_frame,
                id_label,
                service_label,
                username_label,
                password_cell,
                password_value_label,
                created_at_label,
            )

        if self.selected_password_id not in self.password_rows:
            self.selected_password_id = None

        self.update_action_button_states()

    # This function attaches click handlers so a whole row behaves like a selectable item.
    # Inputs:
    #     password_id: The database ID for the row being wired up.
    #     widgets: Every widget that should react when the user clicks the row.
    # Outputs:
    #     None. Event bindings are attached to the widgets.
    def bind_row_selection(
        self,
        password_id: int,
        *widgets,
    ) -> None:
        for widget in widgets:
            widget.bind(
                "<Button-1>",
                lambda _event, current_id=password_id: self.select_password_row(
                    current_id
                ),
            )

    # This function marks one vault row as selected and refreshes the row highlights.
    # Inputs:
    #     password_id: The database ID the user clicked.
    # Outputs:
    #     None. The current selection state is updated.
    def select_password_row(self, password_id: int) -> None:
        self.selected_password_id = password_id

        for current_id, row_frame in self.row_frames.items():
            is_selected = current_id == password_id
            row_frame.configure(
                fg_color=ROW_SELECTED_COLOR if is_selected else ROW_COLOR,
                border_color=ACCENT_COLOR if is_selected else BORDER_COLOR,
            )

        self.update_action_button_states()

    # This function enables or disables Edit/Delete depending on whether a row is selected.
    # Inputs:
    #     None. It uses the current selected_password_id state.
    # Outputs:
    #     None. Button states are updated in place.
    def update_action_button_states(self) -> None:
        has_selection = self.selected_password_id is not None

        self.edit_button.configure(state="normal" if has_selection else "disabled")
        self.delete_button.configure(state="normal" if has_selection else "disabled")

    # This function flips one table row's password between hidden and visible.
    # Inputs:
    #     password_id: The row whose password display should change.
    # Outputs:
    #     None. The table is redrawn with the new visibility state.
    def toggle_row_password_visibility(self, password_id: int) -> None:
        current_state = self.password_visibility.get(password_id, False)
        self.password_visibility[password_id] = not current_state
        self.refresh_vault_rows()

    # This function opens the add-password popup.
    # Inputs:
    #     None. It uses the already active session key.
    # Outputs:
    #     None. A modal add dialog is created.
    def open_add_dialog(self) -> None:
        PasswordDialog(
            parent=self,
            session_key=self.session_key,
            refresh_callback=self.handle_refresh_callback,
            mode="add",
        )

    # This function opens the edit dialog using the currently selected row.
    # Inputs:
    #     None. It uses the selected_password_id stored on the app.
    # Outputs:
    #     None. Either an error message is shown or the edit popup opens.
    def open_edit_dialog(self) -> None:
        if self.selected_password_id is None:
            set_status_message(
                self.main_status_label,
                "Select a row before trying to edit a password.",
                False,
            )
            return

        row = self.password_rows[self.selected_password_id]
        password_id, service, username, _encrypted_password, _created_at = row

        PasswordDialog(
            parent=self,
            session_key=self.session_key,
            refresh_callback=self.handle_refresh_callback,
            mode="edit",
            entry_data={
                "id": password_id,
                "service": service,
                "username": username,
                "password": self.password_cache.get(password_id, ""),
            },
        )

    # This function opens a confirmation popup before deleting the selected row.
    # Inputs:
    #     None. It uses the currently selected password row.
    # Outputs:
    #     None. Either an error is shown or the delete popup opens.
    def open_delete_dialog(self) -> None:
        if self.selected_password_id is None:
            set_status_message(
                self.main_status_label,
                "Select a row before trying to delete a password.",
                False,
            )
            return

        row = self.password_rows[self.selected_password_id]
        password_id, service, username, _encrypted_password, _created_at = row

        DeleteConfirmationDialog(
            parent=self,
            entry_data={
                "id": password_id,
                "service": service,
                "username": username,
            },
            confirm_callback=self.delete_password_entry,
        )

    # This function removes a password row from the database after confirmation.
    # Inputs:
    #     password_id: The ID of the row that should be deleted.
    # Outputs:
    #     tuple[bool, str]: A success flag and a user-facing status message.
    def delete_password_entry(self, password_id: int) -> tuple[bool, str]:
        try:
            db.delete_password(password_id)

            if self.selected_password_id == password_id:
                self.selected_password_id = None

            self.refresh_vault_rows()
            set_status_message(
                self.main_status_label,
                "Password entry deleted successfully.",
                True,
            )
            return True, "Password entry deleted successfully."
        except Exception as error:
            set_status_message(
                self.main_status_label,
                f"Could not delete this password entry: {error}",
                False,
            )
            return False, f"Could not delete this password entry: {error}"

    # This function opens the change-master-password popup.
    # Inputs:
    #     None. It uses the current logged-in session.
    # Outputs:
    #     None. A modal dialog is created.
    def open_change_master_password_dialog(self) -> None:
        ChangeMasterPasswordDialog(self, self.process_master_password_change)

    # This function verifies and applies a master-password change request.
    # Inputs:
    #     current_password: The user's current master password.
    #     new_password: The new password they want to use.
    #     confirm_password: The confirmation copy of the new password.
    # Outputs:
    #     tuple[bool, str]: A success flag and an inline message for the dialog.
    def process_master_password_change(
        self,
        current_password: str,
        new_password: str,
        confirm_password: str,
    ) -> tuple[bool, str]:
        if not current_password or not new_password or not confirm_password:
            return False, "Please fill in all three password fields."

        if not auth.verify_master_password(current_password):
            return False, "The current master password is incorrect."

        if new_password != confirm_password:
            return False, "The new password fields do not match."

        if current_password == new_password:
            return False, "Choose a different password from your current master password."

        new_session_key = enc.derive_key_from_password(new_password)

        success, message = self.reencrypt_vault(self.session_key, new_session_key)
        if not success:
            return False, message

        auth.hash_and_save_master_password(new_password)
        self.session_key = new_session_key
        self.password_visibility.clear()
        self.refresh_vault_rows()
        set_status_message(
            self.main_status_label,
            "Master password changed and the vault was re-encrypted successfully.",
            True,
        )
        return True, "Master password updated successfully."

    # This function re-encrypts every saved password from one session key to another.
    # Inputs:
    #     old_key: The key used to decrypt the currently stored passwords.
    #     new_key: The key that should encrypt the passwords going forward.
    # Outputs:
    #     tuple[bool, str]: A success flag and a human-readable result message.
    def reencrypt_vault(self, old_key: bytes, new_key: bytes) -> tuple[bool, str]:
        rows = db.get_all_passwords()

        for row in rows:
            password_id, service, username, old_encrypted_password, _created_at = row

            try:
                decrypted_password = enc.decrypt_password(old_key, old_encrypted_password)
                new_encrypted_password = enc.encrypt_password(new_key, decrypted_password)
                db.update_password(
                    password_id,
                    service,
                    username,
                    new_encrypted_password,
                )
            except Exception as error:
                return (
                    False,
                    f"Re-encryption failed on entry {password_id}. No further changes were made: {error}",
                )

        return True, "Vault re-encryption completed successfully."

    # This function refreshes the table and shows a status message after add/edit actions.
    # Inputs:
    #     message: The feedback text to show.
    #     success: True for green feedback, False for red feedback.
    # Outputs:
    #     None. The table and message area are updated.
    def handle_refresh_callback(self, message: str, success: bool) -> None:
        self.password_visibility.clear()
        self.refresh_vault_rows()
        set_status_message(self.main_status_label, message, success)

    # This function clears the session and returns the user to the login screen.
    # Inputs:
    #     None. It uses the app's current in-memory session state.
    # Outputs:
    #     None. The user is logged out locally.
    def logout(self) -> None:
        self.session_key = None
        self.selected_password_id = None
        self.password_visibility.clear()
        self.password_cache.clear()
        self.password_rows.clear()
        self.row_frames.clear()
        self.show_login_screen("Logged out successfully.", True)


# This function creates the app object and starts Tkinter's event loop.
# Inputs:
#     None. It uses the classes and constants defined above.
# Outputs:
#     None. The GUI stays open until the user closes it.
def main() -> None:
    app = SecureVaultApp()
    app.mainloop()


if __name__ == "__main__":
    main()
