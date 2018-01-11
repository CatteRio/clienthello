package sun.security.ssl;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Collection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import com.zhibei.json.JSONArray;
import com.zhibei.json.JSONObject;

public class ProxySocketServer implements Runnable {

	Socket socket;
	SSLContext sslContext;

	public ProxySocketServer(Socket socket, SSLContext sslContext) {
		this.socket = socket;
		this.sslContext = sslContext;
	}

	public static void main(String[] args) {
		try {
			String serverKeyStoreFile = "D:\\tomcat.keystore";
			String serverKeyStorePwd = "logiscn";
			String catServerKeyPwd = "logiscn";
			String serverTrustKeyStoreFile = "D:\\tomcat.keystore";
			String serverTrustKeyStorePwd = "logiscn";
			 System.setProperty("javax.net.debug", "ssl,handshake");
			KeyStore serverKeyStore = KeyStore.getInstance("JKS");
			serverKeyStore.load(new FileInputStream(serverKeyStoreFile), serverKeyStorePwd.toCharArray());
			KeyStore serverTrustKeyStore = KeyStore.getInstance("JKS");
			serverTrustKeyStore.load(new FileInputStream(serverTrustKeyStoreFile), serverTrustKeyStorePwd.toCharArray());
			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(serverKeyStore, catServerKeyPwd.toCharArray());
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(serverTrustKeyStore);
			SSLContext sslContext = SSLContext.getInstance("TLSv1");
			sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			
			ServerSocket serverSocket = new ServerSocket(2443);
			while (true) {
				Socket socket = serverSocket.accept();
				ProxySocketServer ps = new ProxySocketServer(socket, sslContext);
				new Thread(ps).start();
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	@Override
	public void run() {
		try {
			InputStream ins = socket.getInputStream();
			byte[] buffer = new byte[0xFF];
			int position = 0;
			SSLCapabilities capabilities = null;
			while (position < SSLExplorer.RECORD_HEADER_SIZE) {
				int count = SSLExplorer.RECORD_HEADER_SIZE - position;
				int n = ins.read(buffer, position, count);
				if (n < 0) {
					throw new Exception("unexpected end of stream!");
				}
				position += n;
			}
			int recordLength = SSLExplorer.getRequiredSize(buffer, 0, position);
			if (buffer.length < recordLength) {
				buffer = Arrays.copyOf(buffer, recordLength);
			}
			while (position < recordLength) {
				int count = recordLength - position;
				int n = ins.read(buffer, position, count);
				if (n < 0) {
					throw new Exception("unexpected end of stream!");
				}
				position += n;
			}
			capabilities = SSLExplorer.explore(buffer, 0, recordLength);
			System.out.println(capabilities.getHelloVersion());
			System.out.println(capabilities.getRecordVersion());
			SSLContext serviceContext = sslContext;
			SSLSocketFactory serviceSocketFac = serviceContext.getSocketFactory();
			// 包装缓冲的字节
			ByteArrayInputStream bais = new ByteArrayInputStream(buffer, 0, position);
			SSLSocket serviceSocket = (SSLSocket) serviceSocketFac.createSocket(socket, bais, true);

			Class<SSLSocketImpl> c = SSLSocketImpl.class;
			Field field = c.getDeclaredField("handshaker");
			field.setAccessible(true);
			Object hander = field.get(serviceSocket);

			Class<?> serverClass = hander.getClass();
			serverClass = serverClass.getSuperclass();
			Field input = serverClass.getDeclaredField("input");
			input.setAccessible(true);
			serviceSocket.startHandshake();
			Object serverInput = input.get(hander);

			Class<?> clientHello = Class.forName("sun.security.ssl.HandshakeMessage$ClientHello");
			Constructor<?> clientHelloConstructor = clientHello.getDeclaredConstructor(Class.forName("sun.security.ssl.HandshakeInStream"),
					int.class);
			clientHelloConstructor.setAccessible(true);

			Class<?> handShakeStream = serverInput.getClass();
			Field r = handShakeStream.getDeclaredField("r");
			r.setAccessible(true);
			Object recorder = r.get(serverInput);
			Class<?> byteArray = recorder.getClass().getSuperclass();
			Field pos = byteArray.getDeclaredField("pos");
			Field count = byteArray.getDeclaredField("count");
			Field buf = byteArray.getDeclaredField("buf");
			pos.setAccessible(true);
			count.setAccessible(true);
			buf.setAccessible(true);
			pos.set(recorder, 0);
			count.set(recorder, buffer.length);
			buf.set(recorder, buffer);
			Method reset = handShakeStream.getDeclaredMethod("reset");
			reset.invoke(serverInput);

			Object clientObject = clientHelloConstructor.newInstance(serverInput, 0);
			JSONObject jsb = new JSONObject();
			jsb.put("version", capabilities.getHelloVersion());
			Field compression = clientHello.getDeclaredField("compression_methods");
			compression.setAccessible(true);
			byte[] compressionMethod = (byte[]) compression.get(clientObject);
			jsb.put("compression", compressionMethod);
			
			Method getCipherSuites = clientHello.getDeclaredMethod("getCipherSuites");
			getCipherSuites.setAccessible(true);
			Object ciphersuits = getCipherSuites.invoke(clientObject);

			Method size = ciphersuits.getClass().getDeclaredMethod("collection");
			size.setAccessible(true);
			Collection<?> ciphersuitCol = (Collection<?>) size.invoke(ciphersuits);
			JSONArray jsarr = new JSONArray();
			for (Object ciphersuit : ciphersuitCol) {
				Field ciphersuitName = ciphersuit.getClass().getDeclaredField("name");
				ciphersuitName.setAccessible(true);
				jsarr.put(ciphersuitName.get(ciphersuit));
			}
			jsb.put("ciphersuits", jsarr);
			PrintWriter writer = new PrintWriter(serviceSocket.getOutputStream(), true);
			String data = jsb.toString();
			writer.println("HTTP/1.1 200 OK");
			writer.println("Server: Apache-Coyote/1.1");
			writer.println("Content-Type: application/json;charset=UTF-8");
			writer.println("Content-Length: " + data.getBytes("utf-8").length);
			writer.println("Access-Control-Allow-Origin:*");
			writer.println("");
			writer.println(data);
			writer.flush();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
