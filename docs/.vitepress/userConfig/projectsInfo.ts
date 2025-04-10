interface Project {
  banner: string; // 图片链接
  title: string; // 项目标题
  description: string; // 项目简介
  link: string; // 项目链接
  tag?: string; // 项目标签
}

/**
 * TODO: 缺项处理
 * 在此处填写你的项目介绍
 */
export const projectsInfo: Project[] = [
  {
    banner: "/project-img/gpt-feishu.png",
    title: "eBPF",
    description:"容器逃逸检测",
    link: "https://github.com/zer0-1s/ehids-agent",
    tag: "Golang",
  },


];
