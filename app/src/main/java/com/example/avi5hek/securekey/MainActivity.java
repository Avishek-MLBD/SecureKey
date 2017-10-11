package com.example.avi5hek.securekey;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import butterknife.BindView;
import butterknife.ButterKnife;
import butterknife.OnClick;

public class MainActivity extends AppCompatActivity {

  private static final String KEY_ENCRYPTED_DATA = "encryptedData";

  @BindView(R.id.edit_input)
  EditText inputEditText;
  @BindView(R.id.button_encrypt)
  Button encryptButton;
  @BindView(R.id.text_encrypted_text)
  TextView encryptedTextView;
  @BindView(R.id.button_decrypt)
  Button decryptButton;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
    ButterKnife.bind(this);
  }

  @OnClick(R.id.button_encrypt)
  void onEncryptButtonClick() {
    String encryptedText = SecurePref.with(getApplicationContext())
        .encrypt(KEY_ENCRYPTED_DATA, inputEditText.getText().toString()).get();
    encryptedTextView.setText(encryptedText);
  }

  @OnClick(R.id.button_decrypt)
  void onDecryptButtonClick() {
    String decryptedText = SecurePref.with(getApplicationContext())
        .decrypt(KEY_ENCRYPTED_DATA).get();
    encryptedTextView.setText(decryptedText);
  }
}
