import torch
import torch.nn as nn
import torch.nn.functional as F

class Attention(nn.Module):
    def __init__(self, hidden_dim):
        super(Attention, self).__init__()
        self.attn = nn.Linear(hidden_dim, 1)

    def forward(self, lstm_output):
        # lstm_output shape: (Batch, Seq_Len, Hidden_Dim)
        
        # Tính trọng số attention (alpha)
        attn_weights = self.attn(lstm_output) # (Batch, Seq_Len, 1)
        attn_weights = F.softmax(attn_weights, dim=1)
        
        # Nhân trọng số với output của LSTM -> Context Vector
        context = torch.sum(attn_weights * lstm_output, dim=1) # (Batch, Hidden_Dim)
        return context, attn_weights

class WAF_Attention_Model(nn.Module):
    def __init__(self, vocab_size, embedding_dim, num_classes=1):
        super().__init__()
        
        # 1. Embedding
        self.embedding = nn.Embedding(vocab_size, embedding_dim)
        
        # 2. CNN Layers (Trích xuất đặc trưng cục bộ)
        self.conv1 = nn.Conv1d(embedding_dim, 128, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(128)
        self.pool1 = nn.MaxPool1d(2)
        self.dropout1 = nn.Dropout(0.2)
        
        self.conv2 = nn.Conv1d(128, 256, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm1d(256)
        self.pool2 = nn.MaxPool1d(2)
        self.dropout2 = nn.Dropout(0.2)
        
        # 3. Bi-Directional LSTM (2 Lớp chồng lên nhau)
        # Tăng hidden_size lên 256 để mô hình "thông minh" hơn
        self.lstm_hidden = 256
        self.lstm = nn.LSTM(input_size=256, # Output channel của conv2
                            hidden_size=self.lstm_hidden, 
                            num_layers=2, # Stack 2 lớp LSTM
                            batch_first=True, 
                            bidirectional=True,
                            dropout=0.3) # Dropout giữa các lớp LSTM
        
        # 4. Attention Mechanism
        # Bi-LSTM output size = hidden * 2
        self.attention = Attention(self.lstm_hidden * 2)
        
        # 5. Fully Connected
        self.fc1 = nn.Linear(self.lstm_hidden * 2, 128)
        self.bn_fc1 = nn.BatchNorm1d(128)
        self.dropout_fc = nn.Dropout(0.4)
        self.output = nn.Linear(128, 1)
        self.sigmoid = nn.Sigmoid()
        
        self.relu = nn.ReLU()

    def forward(self, x):
        # Embedding
        x = self.embedding(x) # (Batch, Seq, Emb)
        
        # CNN (Permute để đúng chiều)
        x = x.permute(0, 2, 1) # (Batch, Emb, Seq)
        x = self.pool1(self.relu(self.bn1(self.conv1(x))))
        x = self.dropout1(x)
        x = self.pool2(self.relu(self.bn2(self.conv2(x))))
        x = self.dropout2(x)
        
        # LSTM (Permute lại)
        x = x.permute(0, 2, 1) # (Batch, New_Seq, 256)
        self.lstm.flatten_parameters()
        lstm_out, (h_n, c_n) = self.lstm(x)
        
        # Attention (Thay vì chỉ lấy last step, ta dùng Attention tổng hợp toàn bộ)
        context_vector, _ = self.attention(lstm_out)
        
        # MLP
        x = self.fc1(context_vector)
        x = self.bn_fc1(x)
        x = self.relu(x)
        x = self.dropout_fc(x)
        
        return self.sigmoid(self.output(x))