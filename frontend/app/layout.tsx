import "./globals.css";

export const metadata = {
  title: "TabPFN Sentinel",
  description: "Evidence-driven network intrusion detection and investigation"
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
